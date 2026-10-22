use std::collections::BTreeMap;

use crate::digest::{md5, md5_parts};
use crate::proto::{DeviceProperty, IssuedTokenReply, append_bytes_field, encoded_bytes_len};

pub type DeviceProperties = BTreeMap<i32, Vec<u8>>;

pub fn property_digest(contents: &[u8], suffix: &[u8]) -> [u8; 32] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = md5_parts(&[contents, suffix]);
    let mut output = [0; 32];
    for (index, byte) in digest.into_iter().enumerate() {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 15)];
    }
    output
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuedToken {
    pub bytes: Vec<u8>,
    pub expires_at: i64,
}

#[derive(Clone, Copy, Debug)]
pub struct TokenPolicy {
    pub token_enabled: bool,
    pub xwid_enabled: bool,
    pub token_refresh_margin: i64,
    pub retry_interval: i64,
    pub xwid_max_age: i64,
    pub xwid_refresh_age: i64,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            token_enabled: true,
            xwid_enabled: false,
            token_refresh_margin: 300,
            retry_interval: 60,
            xwid_max_age: 3600,
            xwid_refresh_age: 3480,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquisitionMode {
    ColdOrExpired,
    RefreshWindow,
}

#[derive(Debug)]
pub struct XwidAcquisition {
    pub xwid: Vec<u8>,
    pub auxiliary: Vec<u8>,
    pub started_at: i64,
    pub elapsed_nanoseconds: i64,
}

impl XwidAcquisition {
    pub fn native_default(started_at: i64, elapsed_nanoseconds: i64) -> Self {
        Self {
            xwid: Vec::new(),
            auxiliary: Vec::new(),
            started_at,
            elapsed_nanoseconds,
        }
    }
}

#[derive(Debug)]
pub struct ReportResponse {
    pub bytes: Vec<u8>,
    pub transport_succeeded: bool,
    pub error_code: u32,
}

#[derive(Debug)]
pub enum ReportDelivery {
    Complete(ReportResponse),
    Pending,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TokenError {
    Resource {
        operation: &'static str,
        message: String,
    },
    PropertyCollection(i32),
    Protobuf {
        code: u32,
        offset: usize,
    },
    PropertyRequestTruncated {
        offset: usize,
    },
    Transport(u32),
}

pub trait TokenResources {
    fn unix_seconds(&mut self) -> i64;
    fn persistent_xwid_switch(&mut self) -> Result<Option<&[u8]>, TokenError>;
    fn acquire_xwid(
        &mut self,
        mode: AcquisitionMode,
    ) -> Result<Option<XwidAcquisition>, TokenError>;
    fn collect_properties(&mut self) -> Result<DeviceProperties, TokenError>;
    fn send_report(
        &mut self,
        method: &str,
        account: &[u8],
        packet: &[u8],
    ) -> Result<ReportDelivery, TokenError>;
}

#[derive(Debug)]
pub struct TokenRead {
    pub bytes: Vec<u8>,
    pub report_error: Option<TokenError>,
    pub first_empty_token: bool,
}

#[derive(Debug, Default)]
pub struct TokenState {
    pub policy: TokenPolicy,
    account_tokens: BTreeMap<Vec<u8>, IssuedToken>,
    active_account: Vec<u8>,
    xwid: Vec<u8>,
    xwid_token: Vec<u8>,
    auxiliary: Vec<u8>,
    xwid_timestamp: i64,
    xwid_acquisition_milliseconds: i64,
    xwid_pending: bool,
    report_pending: bool,
    failed_times: u32,
    last_attempt: i64,
    empty_token_event_recorded: bool,
    xwid_selector: Option<i32>,
}

impl TokenState {
    pub fn initialize_xwid_switch(&mut self, stored_value: Option<&[u8]>) {
        if self.xwid_selector.is_some() {
            return;
        }
        let value = stored_value.unwrap_or_default();
        let value = value.split(|&byte| byte == 0).next().unwrap_or_default();
        let parsed = if value.is_empty() {
            1
        } else {
            parse_atoi(value)
        };
        let selector = if parsed == -1 { 1 } else { parsed };
        self.xwid_selector = if selector == 2 { None } else { Some(selector) };
        self.policy.xwid_enabled = selector == 1;
    }

    pub fn xwid_selector(&self) -> i32 {
        self.xwid_selector.unwrap_or(2)
    }

    pub fn change_account(
        &mut self,
        account: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        let previous_report = self.refresh_active_account(resources);
        self.active_account.clear();
        self.active_account.extend_from_slice(account);
        self.report_pending = false;
        self.last_attempt = 0;
        self.empty_token_event_recorded = false;
        previous_report
    }

    pub fn failed_times(&self) -> u32 {
        self.failed_times
    }

    pub fn last_attempt(&self) -> i64 {
        self.last_attempt
    }

    pub fn report_pending(&self) -> bool {
        self.report_pending
    }

    pub fn account_token(&self, account: &[u8]) -> Option<&IssuedToken> {
        self.account_tokens.get(account)
    }

    pub fn auxiliary(&self) -> &[u8] {
        &self.auxiliary
    }

    pub fn xwid_acquisition_milliseconds(&self) -> i64 {
        self.xwid_acquisition_milliseconds
    }

    pub fn complete_xwid(&mut self, acquisition: XwidAcquisition) {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        self.xwid = acquisition.xwid;
        self.xwid_acquisition_milliseconds = acquisition.elapsed_nanoseconds / 1_000_000;
        if !self.xwid.is_empty() {
            let digest = md5(&self.xwid);
            self.xwid_token.clear();
            self.xwid_token.reserve(12);
            for chunk in digest[..9].chunks_exact(3) {
                let bits =
                    (u32::from(chunk[0]) << 16) | (u32::from(chunk[1]) << 8) | u32::from(chunk[2]);
                self.xwid_token.push(ALPHABET[((bits >> 18) & 63) as usize]);
                self.xwid_token.push(ALPHABET[((bits >> 12) & 63) as usize]);
                self.xwid_token.push(ALPHABET[((bits >> 6) & 63) as usize]);
                self.xwid_token.push(ALPHABET[(bits & 63) as usize]);
            }
        }
        self.auxiliary = acquisition.auxiliary;
        self.xwid_timestamp = acquisition.started_at;
        self.xwid_pending = false;
    }

    pub fn complete_report(
        &mut self,
        captured_account: &[u8],
        response: ReportResponse,
    ) -> Result<(), TokenError> {
        self.report_pending = false;
        if !response.transport_succeeded {
            self.failed_times = self.failed_times.wrapping_add(1);
            return Err(TokenError::Transport(response.error_code));
        }
        match decode_issued_token(&response.bytes) {
            Ok(token) => {
                self.failed_times = 0;
                self.account_tokens.insert(captured_account.to_vec(), token);
                Ok(())
            }
            Err(error) => {
                self.failed_times = self.failed_times.wrapping_add(1);
                Err(error)
            }
        }
    }

    pub fn token(
        &mut self,
        current_account: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<TokenRead, TokenError> {
        let mut bytes = Vec::new();
        if self.xwid_selector.is_none() {
            self.initialize_xwid_switch(resources.persistent_xwid_switch()?);
        }
        if self.policy.xwid_enabled {
            let now = resources.unix_seconds();
            let elapsed = now.wrapping_sub(self.xwid_timestamp);
            let cold_or_expired = self.xwid.is_empty() || elapsed > self.policy.xwid_max_age;
            if cold_or_expired {
                self.acquire(AcquisitionMode::ColdOrExpired, resources)?;
            } else if elapsed > self.policy.xwid_refresh_age {
                self.acquire(AcquisitionMode::RefreshWindow, resources)?;
            } else {
                bytes.extend_from_slice(&self.xwid_token);
            }
        }
        if !self.policy.token_enabled {
            return Ok(TokenRead {
                bytes,
                report_error: None,
                first_empty_token: false,
            });
        }
        let now = resources.unix_seconds();
        let needs_report = match self.account_tokens.get(current_account) {
            Some(token) => {
                let remaining = token.expires_at.wrapping_sub(now);
                if remaining <= 0 {
                    true
                } else {
                    bytes.clear();
                    bytes.extend_from_slice(&token.bytes);
                    remaining < self.policy.token_refresh_margin
                }
            }
            None => true,
        };
        if !needs_report
            || current_account != self.active_account
            || self.active_account.len() < 4
            || self.report_pending
        {
            return Ok(self.finish_read(bytes, None));
        }
        let now = resources.unix_seconds();
        if now.wrapping_sub(self.last_attempt) < self.policy.retry_interval {
            return Ok(self.finish_read(bytes, None));
        }
        self.last_attempt = now;
        let report_error = self.report_for_account(current_account, resources).err();
        Ok(self.finish_read(bytes, report_error))
    }

    pub fn refresh_active_account(
        &mut self,
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        if self.active_account.len() < 4 || self.report_pending {
            return Ok(());
        }
        let account = std::mem::take(&mut self.active_account);
        let result = self.report_for_account(&account, resources);
        self.active_account = account;
        result
    }

    fn report_for_account(
        &mut self,
        account: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        let properties = resources.collect_properties()?;
        let previous = self
            .account_tokens
            .get(account)
            .map_or(&[][..], |token| token.bytes.as_slice());
        let packet = encode_report(properties, previous);
        self.report_pending = true;
        let delivery = match resources.send_report("getToken", account, &packet) {
            Ok(delivery) => delivery,
            Err(error) => {
                self.report_pending = false;
                return Err(error);
            }
        };
        match delivery {
            ReportDelivery::Complete(response) => self.complete_report(account, response),
            ReportDelivery::Pending => Ok(()),
        }
    }

    fn finish_read(&mut self, bytes: Vec<u8>, report_error: Option<TokenError>) -> TokenRead {
        let first_empty_token = bytes.is_empty() && !self.empty_token_event_recorded;
        self.empty_token_event_recorded |= first_empty_token;
        TokenRead {
            bytes,
            report_error,
            first_empty_token,
        }
    }

    pub fn answer_property_challenge(
        &mut self,
        requested_ids: &[u8],
        resources: &mut impl TokenResources,
    ) -> Result<Vec<u8>, TokenError> {
        if requested_ids.len() % 2 != 0 {
            return Err(TokenError::PropertyRequestTruncated {
                offset: requested_ids.len() - 1,
            });
        }
        let mut ids: Vec<i32> = requested_ids
            .chunks_exact(2)
            .map(|bytes| i32::from(i16::from_be_bytes([bytes[0], bytes[1]])))
            .collect();
        ids.sort_unstable();
        ids.dedup();
        let mut properties = resources.collect_properties()?;
        let mut output = Vec::new();
        for id in ids {
            match properties.remove(&id) {
                Some(value) => put_property(id, value, &mut output),
                None => put_missing_property(id, &mut output),
            }
        }
        let previous = self
            .account_tokens
            .get(self.active_account.as_slice())
            .map_or(&[][..], |token| token.bytes.as_slice());
        append_bytes_field(&mut output, 2, previous);
        Ok(output)
    }

    fn acquire(
        &mut self,
        mode: AcquisitionMode,
        resources: &mut impl TokenResources,
    ) -> Result<(), TokenError> {
        if self.xwid_pending {
            return Ok(());
        }
        self.xwid_pending = true;
        match resources.acquire_xwid(mode) {
            Ok(Some(acquisition)) => self.complete_xwid(acquisition),
            Ok(None) => {}
            Err(error) => {
                self.xwid_pending = false;
                return Err(error);
            }
        }
        Ok(())
    }
}

fn parse_atoi(input: &[u8]) -> i32 {
    let mut remaining = input;
    while remaining
        .first()
        .is_some_and(|byte| matches!(*byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c))
    {
        remaining = &remaining[1..];
    }
    let negative = remaining.first() == Some(&b'-');
    if negative || remaining.first() == Some(&b'+') {
        remaining = &remaining[1..];
    }
    let limit = (i64::MAX as u64) + u64::from(negative);
    let mut magnitude = 0u64;
    for &byte in remaining {
        if !byte.is_ascii_digit() {
            break;
        }
        magnitude = magnitude
            .saturating_mul(10)
            .saturating_add(u64::from(byte - b'0'))
            .min(limit);
    }
    if negative {
        (magnitude as i64).wrapping_neg() as i32
    } else {
        magnitude as i32
    }
}

pub fn encode_report(properties: DeviceProperties, previous_token: &[u8]) -> Vec<u8> {
    let capacity = properties
        .iter()
        .map(|(&id, value)| {
            let length = property_length(id, value);
            if length == 0 {
                0
            } else {
                1 + prost::encoding::encoded_len_varint(length as u64) + length
            }
        })
        .sum::<usize>()
        + encoded_bytes_len(previous_token);
    let mut output = Vec::with_capacity(capacity);
    for (id, value) in properties {
        put_property(id, value, &mut output);
    }
    append_bytes_field(&mut output, 2, previous_token);
    output
}

fn property_length(id: i32, value: &[u8]) -> usize {
    let id = id as u32;
    let id_length = if id == 0 {
        0
    } else {
        1 + prost::encoding::encoded_len_varint(u64::from(id))
    };
    id_length + encoded_bytes_len(value)
}

fn put_property(id: i32, value: Vec<u8>, output: &mut Vec<u8>) {
    let property = DeviceProperty {
        id: id as u32,
        value,
    };
    if property.id != 0 || !property.value.is_empty() {
        prost::encoding::message::encode(1, &property, output);
    }
}

fn put_missing_property(id: i32, output: &mut Vec<u8>) {
    let length = property_length(id, b"-1");
    prost::encoding::encode_key(1, prost::encoding::WireType::LengthDelimited, output);
    prost::encoding::encode_varint(length as u64, output);
    if id != 0 {
        prost::encoding::uint32::encode(1, &(id as u32), output);
    }
    append_bytes_field(output, 2, b"-1");
}

pub fn decode_issued_token(input: &[u8]) -> Result<IssuedToken, TokenError> {
    let mut offset = 0;
    let mut token = IssuedTokenReply::default();
    while offset < input.len() {
        let key = read_varint(input, &mut offset)? as u32;
        let field = key >> 3;
        let wire = key & 7;
        match (field, wire) {
            (1, 2) => {
                let value = read_bytes(input, &mut offset)?;
                token.token.clear();
                token.token.extend_from_slice(value);
            }
            (2, 0) => token.expires_at = read_varint(input, &mut offset)?,
            (_, 0) => {
                read_varint(input, &mut offset)?;
            }
            (_, 1) => advance(input, &mut offset, 8)?,
            (_, 2) => {
                read_bytes(input, &mut offset)?;
            }
            (_, 5) => advance(input, &mut offset, 4)?,
            _ => {
                return Err(TokenError::Protobuf {
                    code: 0x155,
                    offset,
                });
            }
        }
    }
    Ok(IssuedToken {
        bytes: token.token,
        expires_at: token.expires_at as i64,
    })
}

fn read_varint(input: &[u8], offset: &mut usize) -> Result<u64, TokenError> {
    let mut value = 0u64;
    for shift in (0..70).step_by(7) {
        let byte = *input.get(*offset).ok_or(TokenError::Protobuf {
            code: 0x101,
            offset: *offset,
        })?;
        *offset += 1;
        value |= u64::from(byte & 0x7f).wrapping_shl(shift);
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(TokenError::Protobuf {
        code: 0x102,
        offset: *offset,
    })
}

fn read_bytes<'a>(input: &'a [u8], offset: &mut usize) -> Result<&'a [u8], TokenError> {
    let length = read_varint(input, offset)? as u32 as usize;
    let start = *offset;
    advance(input, offset, length)?;
    Ok(&input[start..*offset])
}

fn advance(input: &[u8], offset: &mut usize, length: usize) -> Result<(), TokenError> {
    let end = offset
        .checked_add(length)
        .filter(|&end| end <= input.len())
        .ok_or(TokenError::Protobuf {
            code: 0x101,
            offset: *offset,
        })?;
    *offset = end;
    Ok(())
}
