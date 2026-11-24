//! `duvet_e2e_free` wipes a reply before it frees it: a reply may hold a secret (a recovery key, a
//! key in an approval or a transfer), whose bytes would otherwise stay in freed memory. The global
//! allocator here looks at the block it's handed back, while it's still allocated.

use std::alloc::{GlobalAlloc, Layout, System};
use std::ffi::CString;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use duvet_e2e_ffi::{duvet_e2e_free, duvet_e2e_handle};

/// The block whose freeing is watched, whether it was freed, and whether its bytes were all 0 then.
static WATCHED: AtomicPtr<u8> = AtomicPtr::new(null_mut());
static FREED: AtomicBool = AtomicBool::new(false);
static WIPED: AtomicBool = AtomicBool::new(false);

struct Watching;

unsafe impl GlobalAlloc for Watching {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: the caller's layout, handed on.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if !ptr.is_null() && ptr == WATCHED.load(Ordering::SeqCst) {
            // SAFETY: the block is still allocated, `layout.size()` bytes at `ptr`.
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            WIPED.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
            FREED.store(true, Ordering::SeqCst);
        }
        // SAFETY: the caller's block and layout, handed on.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watching = Watching;

#[test]
fn a_reply_is_wiped_before_it_is_freed() {
    // A reply needs no open core: an unknown handle answers an error.
    let command = CString::new(r#"{"cmd":"status"}"#).unwrap();
    // SAFETY: a NUL-terminated command, and a handle that names no core.
    let reply = unsafe { duvet_e2e_handle(0, command.as_ptr()) };
    assert!(!reply.is_null());
    WATCHED.store(reply.cast(), Ordering::SeqCst);
    // SAFETY: the reply `duvet_e2e_handle` gave, freed once.
    unsafe { duvet_e2e_free(reply) };
    assert!(FREED.load(Ordering::SeqCst), "the reply was freed");
    assert!(WIPED.load(Ordering::SeqCst), "its bytes were wiped first");
}
