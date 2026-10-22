use std::ffi::c_void;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr;
use std::sync::Mutex;

use crate::bridge::Bridge;

const SUCCESS: i32 = 0;
const ERROR: i32 = 1;
const PANIC: i32 = 2;

struct Handle {
    bridge: Mutex<Bridge>,
}

fn valid_pointer<T>(pointer: *const T) -> bool {
    !pointer.is_null() && pointer.is_aligned()
}

unsafe fn output_call(
    output: *mut *mut u8,
    output_len: *mut usize,
    operation: impl FnOnce() -> Result<Vec<u8>, String>,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let valid_output = valid_pointer(output);
        let valid_len = valid_pointer(output_len);
        if valid_output {
            unsafe { output.write(ptr::null_mut()) };
        }
        if valid_len {
            unsafe { output_len.write(0) };
        }
        if !valid_output || !valid_len {
            return ERROR;
        }
        let (status, bytes) = match catch_unwind(AssertUnwindSafe(operation)) {
            Ok(Ok(bytes)) => (SUCCESS, bytes),
            Ok(Err(error)) => (ERROR, error.into_bytes()),
            Err(_) => (PANIC, b"Rust signer panicked".to_vec()),
        };
        if !bytes.is_empty() {
            let bytes = bytes.into_boxed_slice();
            let len = bytes.len();
            let buffer = Box::into_raw(bytes).cast::<u8>();
            unsafe {
                output.write(buffer);
                output_len.write(len);
            }
        }
        status
    }))
    .unwrap_or(PANIC)
}

/// Create an independent persistent bridge without configuration or filesystem IO.
///
/// # Safety
/// All output pointers must be writable, aligned, nonoverlapping slots. The
/// returned handle is owned by the caller until exactly one destroy call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn w_create(
    handle: *mut *mut c_void,
    error: *mut *mut u8,
    error_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        let valid_handle = valid_pointer(handle);
        if valid_handle {
            unsafe { handle.write(ptr::null_mut()) };
        }
        unsafe {
            output_call(error, error_len, || {
                if !valid_handle {
                    return Err("handle output must be non-null and aligned".into());
                }
                let owned = Box::new(Handle {
                    bridge: Mutex::new(Bridge::default()),
                });
                handle.write(Box::into_raw(owned).cast::<c_void>());
                Ok(Vec::new())
            })
        }
    }))
    .unwrap_or(PANIC)
}

/// Sign a full bridge JSON request containing caller-provided device resources.
///
/// # Safety
/// The handle must be live and must not be destroyed during this call. Request
/// memory must be readable for `request_len` bytes (null is allowed only for an
/// empty request). Output slots must be writable, aligned and nonoverlapping,
/// and may not overlap the request or handle. Calls on one handle serialize.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn w_sign(
    handle: *mut c_void,
    request: *const u8,
    request_len: usize,
    output: *mut *mut u8,
    output_len: *mut usize,
) -> i32 {
    unsafe {
        output_call(output, output_len, || {
            let handle = handle.cast::<Handle>();
            if !valid_pointer(handle) {
                return Err("signer handle must be non-null and aligned".into());
            }
            if request_len > isize::MAX as usize {
                return Err("request length exceeds the addressable slice size".into());
            }
            let request = if request_len == 0 {
                &[]
            } else {
                if request.is_null() {
                    return Err("nonempty request requires a non-null buffer".into());
                }
                std::slice::from_raw_parts(request, request_len)
            };
            let mut bridge = (*handle)
                .bridge
                .lock()
                .map_err(|_| "signer state is poisoned after a previous panic".to_owned())?;
            Ok(bridge.respond(request))
        })
    }
}

/// Release a signer handle. A null handle is a no-op.
///
/// # Safety
/// A non-null handle must come from create, must not have been destroyed, and
/// must not be in use by any other call. This also applies to waiting sign calls.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn w_destroy(handle: *mut c_void) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        let handle = handle.cast::<Handle>();
        if valid_pointer(handle) {
            unsafe { drop(Box::from_raw(handle)) };
        }
    }));
}

/// Release one output buffer. A null buffer is a no-op.
///
/// # Safety
/// A non-null buffer must be an unfreed output from create/sign, paired with its
/// original length. No other code may use the buffer after this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn w_buffer_free(buffer: *mut u8, len: usize) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !buffer.is_null() && len <= isize::MAX as usize {
            unsafe { drop(Box::from_raw(ptr::slice_from_raw_parts_mut(buffer, len))) };
        }
    }));
}
