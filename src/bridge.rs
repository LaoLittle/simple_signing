use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::command_policy::CommandPolicyState;
use crate::extra::ExtraEntropy;
use crate::metadata::{EntropyRead, MetadataResources, MetadataState};
use crate::token::{
    AcquisitionMode, DeviceProperties, ReportDelivery, ReportResponse, TokenError, TokenResources,
    XwidAcquisition,
};
use crate::{Context, SignError, SignResources, Signer};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRequest {
    uin: String,
    qua: String,
    machine_id: String,
    cmd: String,
    seq: i32,
    buffer: String,
    clock_ns: Option<u64>,
    cache16: Option<String>,
    counter: Option<u16>,
    footer_seed: Option<String>,
    #[serde(default)]
    sequence_only: bool,
    #[serde(default = "enabled")]
    sign_enabled: bool,
    #[serde(default = "enabled")]
    token_enabled: bool,
    xwid_enabled: Option<bool>,
    persistent_xwid_switch: Option<String>,
    channel_uuid: Option<String>,
    #[serde(default)]
    random_words: Vec<u32>,
    metadata: Option<WireMetadata>,
    properties: Option<BTreeMap<String, String>>,
    report_response: Option<WireReportResponse>,
    #[serde(default)]
    completions: Vec<WireCompletion>,
    xwid: Option<WireXwid>,
}

fn enabled() -> bool {
    true
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct WireMetadata {
    checksum_seconds: Option<u32>,
    trailer_seconds: Option<u32>,
    entropy: Option<WireEntropy>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
enum WireEntropy {
    Complete { bytes: String },
    Short { bytes: String },
    Unavailable { bytes: Option<String> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReportResponse {
    buffer: String,
    success: bool,
    error_code: u32,
}

impl WireReportResponse {
    fn decode(self, field: &str) -> Result<ReportResponse, String> {
        Ok(ReportResponse {
            bytes: decode_hex(&self.buffer, &format!("{field}.buffer"))?,
            transport_succeeded: self.success,
            error_code: self.error_code,
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCompletion {
    uin: String,
    buffer: String,
    success: bool,
    error_code: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireXwid {
    buffer: String,
    auxiliary: String,
    started_at: i64,
    elapsed_ns: i64,
}

struct Request {
    context: Context,
    command: String,
    sequence: i32,
    body: Vec<u8>,
    cache: Option<[u8; 16]>,
    counter: Option<u16>,
    channel_uuid: Option<[u8; 32]>,
    footer_seed: Option<[u8; 48]>,
    sequence_only: bool,
    sign_enabled: bool,
    token_enabled: bool,
    xwid_enabled: Option<bool>,
    completions: Vec<(Vec<u8>, ReportResponse)>,
    resources: Resources,
}

fn decode_hex(value: &str, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(value).map_err(|_| format!("{field} must be an even-length hexadecimal string"))
}

fn decode_array<const N: usize>(value: &str, field: &str) -> Result<[u8; N], String> {
    decode_hex(value, field)?
        .try_into()
        .map_err(|_| format!("{field} must contain exactly {N} bytes"))
}

fn system_clock_ns() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before UNIX_EPOCH: {error}"))?
        .as_nanos()
        .try_into()
        .map_err(|_| "system clock nanoseconds exceed u64".into())
}

fn system_unix_seconds() -> Result<i64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("system clock is before UNIX_EPOCH: {error}"))?
        .as_secs()
        .try_into()
        .map_err(|_| "system clock seconds exceed i64".into())
}

impl WireRequest {
    fn decode(self) -> Result<Request, String> {
        let body = decode_hex(&self.buffer, "buffer")?;
        let cache = self
            .cache16
            .as_deref()
            .map(|value| decode_array(value, "cache16"))
            .transpose()?;
        let channel_uuid = self
            .channel_uuid
            .as_deref()
            .map(|value| decode_array(value, "channel_uuid"))
            .transpose()?;
        let footer_seed = self
            .footer_seed
            .as_deref()
            .map(|value| decode_array(value, "footer_seed"))
            .transpose()?;
        let metadata = self.metadata.unwrap_or_default();
        let entropy = match metadata.entropy {
            Some(WireEntropy::Complete { bytes }) => Some(EntropyRead::Complete(decode_array(
                &bytes,
                "metadata.entropy.bytes",
            )?)),
            Some(WireEntropy::Short { bytes }) => Some(EntropyRead::ShortRead(decode_array(
                &bytes,
                "metadata.entropy.bytes",
            )?)),
            Some(WireEntropy::Unavailable { bytes }) => {
                if let Some(bytes) = bytes {
                    let _: [u8; 16] = decode_array(&bytes, "metadata.entropy.bytes")?;
                }
                Some(EntropyRead::Unavailable)
            }
            None => None,
        };
        let properties = self
            .properties
            .map(|properties| {
                let mut decoded = DeviceProperties::new();
                for (key, value) in properties {
                    let digits = key.strip_prefix('-').unwrap_or(&key);
                    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(format!(
                            "properties key {key:?} must be a signed 32-bit decimal ID"
                        ));
                    }
                    let id = key.parse::<i32>().map_err(|_| {
                        format!("properties key {key:?} must be a signed 32-bit decimal ID")
                    })?;
                    let value = decode_hex(&value, &format!("properties[{key:?}]"))?;
                    if decoded.insert(id, value).is_some() {
                        return Err(format!("properties contains duplicate numeric ID {id}"));
                    }
                }
                Ok(decoded)
            })
            .transpose()?;
        let report_response = self
            .report_response
            .map(|response| response.decode("report_response"))
            .transpose()?;
        let mut completions = Vec::with_capacity(self.completions.len());
        for (index, completion) in self.completions.into_iter().enumerate() {
            let response = WireReportResponse {
                buffer: completion.buffer,
                success: completion.success,
                error_code: completion.error_code,
            }
            .decode(&format!("completions[{index}]"))?;
            let mut account = completion.uin.into_bytes();
            if let Some(end) = account.iter().position(|&byte| byte == 0) {
                account.truncate(end);
            }
            completions.push((account, response));
        }
        let xwid = self
            .xwid
            .map(|xwid| {
                Ok::<_, String>(XwidAcquisition {
                    xwid: decode_hex(&xwid.buffer, "xwid.buffer")?,
                    auxiliary: decode_hex(&xwid.auxiliary, "xwid.auxiliary")?,
                    started_at: xwid.started_at,
                    elapsed_nanoseconds: xwid.elapsed_ns,
                })
            })
            .transpose()?;
        let persistent_xwid_switch = self
            .persistent_xwid_switch
            .as_deref()
            .map(|value| decode_hex(value, "persistent_xwid_switch"))
            .transpose()?;
        let token_seconds = match self.clock_ns {
            Some(clock_ns) => (clock_ns as i64).div_euclid(1_000_000_000),
            None => system_unix_seconds()?,
        };
        let replay_seconds = self
            .clock_ns
            .map(|clock_ns| (clock_ns as i64).div_euclid(1_000_000_000) as u32);
        Ok(Request {
            context: Context::new(
                self.uin.into_bytes(),
                self.qua.into_bytes(),
                self.machine_id.into_bytes(),
            ),
            command: self.cmd,
            sequence: self.seq,
            body,
            cache,
            counter: self.counter,
            channel_uuid,
            footer_seed,
            sequence_only: self.sequence_only,
            sign_enabled: self.sign_enabled,
            token_enabled: self.token_enabled,
            xwid_enabled: self.xwid_enabled,
            completions,
            resources: Resources {
                clock_ns: self.clock_ns,
                token_seconds,
                system_random: self.random_words.is_empty(),
                system_words: None,
                random_words: self.random_words.into_iter(),
                random_words_consumed: 0,
                checksum_seconds: metadata.checksum_seconds.or(replay_seconds),
                trailer_seconds: metadata.trailer_seconds.or(replay_seconds),
                entropy,
                properties,
                persistent_xwid_switch,
                report_response,
                xwid,
                reports: Vec::new(),
            },
        })
    }
}

struct Resources {
    clock_ns: Option<u64>,
    token_seconds: i64,
    system_random: bool,
    system_words: Option<std::array::IntoIter<u32, 8>>,
    random_words: std::vec::IntoIter<u32>,
    random_words_consumed: usize,
    checksum_seconds: Option<u32>,
    trailer_seconds: Option<u32>,
    entropy: Option<EntropyRead>,
    properties: Option<DeviceProperties>,
    persistent_xwid_switch: Option<Vec<u8>>,
    report_response: Option<ReportResponse>,
    xwid: Option<XwidAcquisition>,
    reports: Vec<Report>,
}

impl ExtraEntropy for Resources {
    type Error = String;

    fn clock_ns(&mut self) -> Result<u64, Self::Error> {
        match self.clock_ns {
            Some(clock_ns) => Ok(clock_ns),
            None => system_clock_ns(),
        }
    }

    fn random_u32(&mut self) -> Result<u32, Self::Error> {
        let word = match self.random_words.next() {
            Some(word) => word,
            None if self.system_random => {
                if self
                    .system_words
                    .as_ref()
                    .is_none_or(|words| words.len() == 0)
                {
                    let mut bytes = [0; 32];
                    getrandom::fill(&mut bytes)
                        .map_err(|error| format!("OS UUID entropy unavailable: {error}"))?;
                    let words = core::array::from_fn(|index| {
                        u32::from_le_bytes(bytes[index * 4..index * 4 + 4].try_into().unwrap())
                    });
                    self.system_words = Some(words.into_iter());
                }
                self.system_words
                    .as_mut()
                    .and_then(Iterator::next)
                    .expect("OS entropy batch contains eight words")
            }
            None => {
                return Err(format!(
                    "random_words exhausted after {} words; cold channel UUID generation requires eight words",
                    self.random_words_consumed,
                ));
            }
        };
        self.random_words_consumed += 1;
        Ok(word)
    }
}

impl TokenResources for Resources {
    fn unix_seconds(&mut self) -> i64 {
        self.token_seconds
    }

    fn persistent_xwid_switch(&mut self) -> Result<Option<&[u8]>, TokenError> {
        Ok(self.persistent_xwid_switch.as_deref())
    }

    fn acquire_xwid(
        &mut self,
        _mode: AcquisitionMode,
    ) -> Result<Option<XwidAcquisition>, TokenError> {
        Ok(Some(match &self.xwid {
            Some(xwid) => XwidAcquisition {
                xwid: xwid.xwid.clone(),
                auxiliary: xwid.auxiliary.clone(),
                started_at: xwid.started_at,
                elapsed_nanoseconds: xwid.elapsed_nanoseconds,
            },

            None => XwidAcquisition::native_default(self.unix_seconds(), 0),
        }))
    }

    fn collect_properties(&mut self) -> Result<DeviceProperties, TokenError> {
        self.properties.clone().ok_or_else(|| TokenError::Resource {
            operation: "collect_properties",
            message: "properties required".into(),
        })
    }

    fn send_report(
        &mut self,
        method: &str,
        account: &[u8],
        packet: &[u8],
    ) -> Result<ReportDelivery, TokenError> {
        let uin = std::str::from_utf8(account).map_err(|error| TokenError::Resource {
            operation: "send_report",
            message: format!("captured UIN is not UTF-8: {error}"),
        })?;
        self.reports.push(Report {
            method: method.to_owned(),
            uin: uin.to_owned(),
            buffer: hex::encode(packet),
        });
        Ok(match &self.report_response {
            Some(response) => ReportDelivery::Complete(ReportResponse {
                bytes: response.bytes.clone(),
                transport_succeeded: response.transport_succeeded,
                error_code: response.error_code,
            }),
            None => ReportDelivery::Pending,
        })
    }
}

impl SignResources for Resources {
    fn metadata_resources(
        &mut self,
        needs_entropy: bool,
    ) -> Result<MetadataResources, Self::Error> {
        let entropy_read = match self.entropy {
            Some(entropy) => entropy,
            None if needs_entropy => {
                let mut bytes = [0; 16];
                getrandom::fill(&mut bytes)
                    .map_err(|error| format!("OS metadata entropy unavailable: {error}"))?;
                EntropyRead::Complete(bytes)
            }

            None => EntropyRead::Unavailable,
        };

        let checksum_seconds = match self.checksum_seconds {
            Some(seconds) => seconds,
            None => system_unix_seconds()? as u32,
        };
        let trailer_seconds = match self.trailer_seconds {
            Some(seconds) => seconds,
            None => system_unix_seconds()? as u32,
        };
        Ok(MetadataResources {
            checksum_seconds,
            trailer_seconds,
            entropy_read,
        })
    }
}

#[derive(Serialize)]
struct Report {
    method: String,
    uin: String,
    buffer: String,
}

#[derive(Serialize)]
struct Data {
    sign: String,
    token: String,
    extra: String,
}

#[derive(Serialize)]
struct State {
    counter: u16,
    cache16: String,
    failed_times: u32,
    last_attempt: i64,
    report_pending: bool,
}

impl From<&Signer> for State {
    fn from(signer: &Signer) -> Self {
        Self {
            counter: signer.command_policy.counter(),
            cache16: hex::encode(signer.metadata.cached_resource()),
            failed_times: signer.tokens.failed_times(),
            last_attempt: signer.tokens.last_attempt(),
            report_pending: signer.tokens.report_pending(),
        }
    }
}

#[derive(Serialize)]
struct Response {
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Data>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<State>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reports: Option<Vec<Report>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token_error: Option<String>,
}

impl Response {
    fn error(error: String) -> Self {
        Self {
            data: None,
            error: Some(error),
            state: None,
            reports: None,
            token_error: None,
        }
    }

    fn into_bytes(self) -> Vec<u8> {
        serde_json::to_vec(&self).expect("bridge response contains only JSON-serializable values")
    }
}

#[derive(Default)]
pub struct Bridge {
    signer: Signer,
    initialized: bool,
}

impl Bridge {
    pub fn respond(&mut self, request: &[u8]) -> Vec<u8> {
        self.process(serde_json::from_slice(request)).into_bytes()
    }

    fn process(&mut self, wire: Result<WireRequest, serde_json::Error>) -> Response {
        let wire = match wire {
            Ok(wire) => wire,
            Err(error) => return Response::error(format!("invalid request: {error}")),
        };
        let request = match wire.decode() {
            Ok(request) => request,
            Err(error) => return Response::error(error),
        };
        self.sign(request)
    }

    fn sign(&mut self, mut request: Request) -> Response {
        let mut token_errors = Vec::new();
        let result = (|| {
            if !self.initialized || self.signer.context() != &request.context {
                self.initialized = true;
                let result = self
                    .signer
                    .initialize(request.context, &mut request.resources);
                if let Some(error) = self.signer.take_token_error() {
                    token_errors.push(format!("initialize: {error:?}"));
                }
                result.map_err(|error| format!("initialize failed: {error:?}"))?;
            }
            if let Some(cache) = request.cache {
                self.signer.metadata = MetadataState::with_cached_resource(cache);
            }
            if let Some(counter) = request.counter {
                self.signer.command_policy = CommandPolicyState::with_counter(counter);
            }
            if let Some(uuid) = request.channel_uuid {
                self.signer.extra.channel_uuid = Some(uuid);
            }
            if let Some(seed) = request.footer_seed {
                self.signer.set_footer_seed(&seed);
            }
            self.signer.sequence_only = request.sequence_only;
            self.signer.sign_enabled = request.sign_enabled;
            self.signer.tokens.policy.token_enabled = request.token_enabled;
            if let Some(enabled) = request.xwid_enabled {
                self.signer.tokens.policy.xwid_enabled = enabled;
            }
            for (account, response) in request.completions {
                if let Err(error) = self.signer.tokens.complete_report(&account, response) {
                    token_errors.push(format!(
                        "completion for {:?}: {error:?}",
                        String::from_utf8_lossy(&account)
                    ));
                }
            }
            self.signer
                .sign(
                    &request.command,
                    request.sequence,
                    &request.body,
                    &mut request.resources,
                )
                .map_err(|error| match error {
                    SignError::Entropy(error) => format!("sign resources: {error}"),
                    SignError::Token(error) => format!("sign token: {error:?}"),
                })
        })();
        if let Some(error) = self.signer.take_token_error() {
            token_errors.push(format!("token: {error:?}"));
        }
        let (data, error) = match result {
            Ok(info) => (
                Some(Data {
                    sign: hex::encode(info.sign.as_ref()),
                    token: hex::encode(info.token),
                    extra: hex::encode(info.extra),
                }),
                None,
            ),
            Err(error) => (None, Some(error)),
        };
        Response {
            data,
            error,
            state: Some(State::from(&self.signer)),
            reports: Some(request.resources.reports),
            token_error: if token_errors.is_empty() {
                None
            } else {
                Some(token_errors.join("; "))
            },
        }
    }
}
