//! Explicit unsafe C boundary; the parser dependency still forbids unsafe code.
//! Callers must supply valid readable/writable allocations for pointer+length
//! pairs. Null checks cannot establish the validity of arbitrary non-null pointers.
use pcap_evidence::{
    engine::{self, Config},
    report,
};
use std::{
    collections::BTreeMap,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Mutex, OnceLock},
};
const OK: i32 = 0;
const INVALID: i32 = 1;
const LIMIT: i32 = 2;
const MISSING: i32 = 3;
const ANALYSIS: i32 = 4;
const PANIC: i32 = 5;
const SMALL: i32 = 6;
struct Handle {
    input: Vec<u8>,
    output: Vec<u8>,
    max_input: usize,
    max_output: usize,
    analyzed: bool,
    successful: bool,
}
#[derive(Default)]
struct State {
    next: u64,
    handles: BTreeMap<u64, Handle>,
}
static STATE: OnceLock<Mutex<State>> = OnceLock::new();
fn guarded(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(PANIC)
}
fn access(f: impl FnOnce(&mut State) -> i32) -> i32 {
    let lock = STATE.get_or_init(|| Mutex::new(State::default()));
    match lock.lock() {
        Ok(mut state) => f(&mut state),
        Err(_) => PANIC,
    }
}
#[no_mangle]
pub extern "C" fn pcap_abi_version() -> u32 {
    1
}
/// # Safety
/// `output` must point to one live, aligned, writable u64 allocation.
#[no_mangle]
pub unsafe extern "C" fn pcap_create(max_input: usize, max_output: usize, output: *mut u64) -> i32 {
    guarded(|| {
        if output.is_null()
            || max_input == 0
            || max_output == 0
            || max_input > 64 * 1024 * 1024
            || max_output > 64 * 1024 * 1024
        {
            return INVALID;
        }
        access(|s| {
            if s.handles.len() >= 8 {
                return LIMIT;
            }
            let Some(id) = s.next.checked_add(1) else {
                return LIMIT;
            };
            s.next = id;
            s.handles.insert(
                id,
                Handle {
                    input: Vec::new(),
                    output: Vec::new(),
                    max_input,
                    max_output,
                    analyzed: false,
                    successful: false,
                },
            );
            unsafe { output.write(id) };
            OK
        })
    })
}
/// # Safety
/// For nonzero length, data must be a valid readable allocation of that length.
#[no_mangle]
pub unsafe extern "C" fn pcap_feed(id: u64, data: *const u8, length: usize) -> i32 {
    guarded(|| {
        if length > 64 * 1024 * 1024 || (length > 0 && data.is_null()) {
            return INVALID;
        }
        access(|s| {
            let Some(h) = s.handles.get_mut(&id) else {
                return MISSING;
            };
            if h.analyzed {
                return INVALID;
            }
            if h.input
                .len()
                .checked_add(length)
                .is_none_or(|n| n > h.max_input)
            {
                return LIMIT;
            }
            if h.input.try_reserve(length).is_err() {
                return LIMIT;
            }
            if length > 0 {
                let bytes = unsafe { std::slice::from_raw_parts(data, length) };
                h.input.extend_from_slice(bytes);
            }
            OK
        })
    })
}
#[no_mangle]
pub extern "C" fn pcap_analyze(id: u64) -> i32 {
    guarded(|| {
        access(|s| {
            let Some(h) = s.handles.get_mut(&id) else {
                return MISSING;
            };
            if h.analyzed {
                return INVALID;
            }
            h.analyzed = true;
            let mut c = Config::default();
            c.limits.max_input_bytes = h.max_input;
            match engine::analyze(&h.input, c) {
                Ok(a) => match report::analysis(&a, false).encode_bounded_line(h.max_output) {
                    Ok(v) => {
                        h.output = v.into_bytes();
                        h.successful = true;
                        OK
                    }
                    Err(_) => LIMIT,
                },
                Err(_) => ANALYSIS,
            }
        })
    })
}
/// # Safety
/// output must point to one valid writable usize. The returned length is exact.
#[no_mangle]
pub unsafe extern "C" fn pcap_output_size(id: u64, output: *mut usize) -> i32 {
    guarded(|| {
        if output.is_null() {
            return INVALID;
        }
        access(|s| {
            let Some(h) = s.handles.get(&id) else {
                return MISSING;
            };
            if !h.successful {
                return INVALID;
            }
            unsafe { output.write(h.output.len()) };
            OK
        })
    })
}
/// # Safety
/// destination must be writable for capacity bytes; written must point to a live
/// usize. Output is NOT NUL terminated. On SMALL no destination bytes are changed.
#[no_mangle]
pub unsafe extern "C" fn pcap_copy_output(
    id: u64,
    destination: *mut u8,
    capacity: usize,
    written: *mut usize,
) -> i32 {
    guarded(|| {
        if written.is_null() || (capacity > 0 && destination.is_null()) {
            return INVALID;
        }
        access(|s| {
            let Some(h) = s.handles.get(&id) else {
                return MISSING;
            };
            if !h.successful {
                return INVALID;
            }
            unsafe { written.write(h.output.len()) };
            if capacity < h.output.len() {
                return SMALL;
            }
            if !h.output.is_empty() {
                unsafe {
                    std::ptr::copy_nonoverlapping(h.output.as_ptr(), destination, h.output.len())
                };
            }
            OK
        })
    })
}
#[no_mangle]
pub extern "C" fn pcap_destroy(id: u64) -> i32 {
    guarded(|| {
        access(|s| {
            if s.handles.remove(&id).is_some() {
                OK
            } else {
                MISSING
            }
        })
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lifecycle_and_invalid_capture() {
        let mut id = 0;
        assert_eq!(unsafe { pcap_create(1024, 4096, &mut id) }, OK);
        assert_eq!(unsafe { pcap_feed(id, [1u8, 2, 3].as_ptr(), 3) }, OK);
        assert_eq!(pcap_analyze(id), ANALYSIS);
        let mut length = 0;
        assert_eq!(unsafe { pcap_output_size(id, &mut length) }, INVALID);
        assert_eq!(unsafe { pcap_feed(id, std::ptr::null(), 0) }, INVALID);
        assert_eq!(pcap_destroy(id), OK);
        assert_eq!(pcap_destroy(id), MISSING);
    }
    #[test]
    fn invalid_pointer_and_budget() {
        assert_eq!(unsafe { pcap_create(1, 1, std::ptr::null_mut()) }, INVALID);
        let mut id = 0;
        assert_eq!(unsafe { pcap_create(2, 4096, &mut id) }, OK);
        assert_eq!(unsafe { pcap_feed(id, [0u8; 3].as_ptr(), 3) }, LIMIT);
        assert_eq!(pcap_destroy(id), OK);
    }
}
