//! The database's key leaves no copy in the memory the core frees as it opens: the key's hex and
//! the statement that hands it to SQLCipher are wiped first. A test binary of its own, since it
//! watches every block the process frees.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, Ordering};

use duvet_e2e::{Core, OpenConfig};

/// The bytes 0 to 31, whose hex starts with `NEEDLE`.
const KEY: [u8; 32] = {
    let mut key = [0; 32];
    let mut byte = 0;
    while byte < 32 {
        key[byte] = byte as u8;
        byte += 1;
    }
    key
};
const NEEDLE: &[u8] = b"0001020304050607";

static WATCHING: AtomicBool = AtomicBool::new(false);
static SEEN: AtomicBool = AtomicBool::new(false);

/// The system's allocator, which looks into each block freed while the test watches.
struct Watcher;

unsafe impl GlobalAlloc for Watcher {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHING.load(Ordering::SeqCst) {
            // SAFETY: the block is still allocated and `layout.size()` bytes long. Its unwritten
            // bytes are read as they are, as only a match matters.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(NEEDLE.len()).any(|window| window == NEEDLE) {
                SEEN.store(true, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Watcher = Watcher;

#[test]
fn freed_memory_never_holds_the_key() {
    let dir = tempfile::tempdir().unwrap();
    let config = OpenConfig::new(dir.path().join("core.db"), KEY);
    WATCHING.store(true, Ordering::SeqCst);
    let core = Core::open(config);
    WATCHING.store(false, Ordering::SeqCst);
    core.unwrap().close();
    assert!(
        !SEEN.load(Ordering::SeqCst),
        "a freed block held the key's hex"
    );
}
