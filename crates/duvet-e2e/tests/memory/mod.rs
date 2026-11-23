//! A global allocator that counts what its test binary holds, for the tests that bound memory. A
//! binary that uses it runs its tests one at a time (`ONE_AT_A_TIME`), so nothing else allocates
//! while one measures. SQLite's own allocations go through its allocator, not this one; SQLite
//! counts them itself, and [`peak_during`] reads that count too.

// Each test file uses its share of these.
#![allow(dead_code)]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

/// What this binary holds now, and the most it held since the last measure began.
static HELD: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

struct Counting;

// SAFETY: every call goes to the system's allocator as it came; the counters only watch.
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: as the caller of `alloc` promised.
        let block = unsafe { System.alloc(layout) };
        if !block.is_null() {
            grew(layout.size());
        }
        block
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: as the caller of `dealloc` promised.
        unsafe { System.dealloc(block, layout) };
        HELD.fetch_sub(layout.size(), Relaxed);
    }

    unsafe fn realloc(&self, block: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: as the caller of `realloc` promised.
        let moved = unsafe { System.realloc(block, layout, size) };
        if !moved.is_null() {
            if size > layout.size() {
                grew(size - layout.size());
            } else {
                HELD.fetch_sub(layout.size() - size, Relaxed);
            }
        }
        moved
    }
}

fn grew(bytes: usize) {
    let held = HELD.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(held, Relaxed);
}

#[global_allocator]
static COUNTING: Counting = Counting;

/// One test at a time: each measures the whole binary.
pub static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

pub const MIB: usize = 1024 * 1024;

/// What `f` returns, and the most held at once while it ran beyond what was held as it began: by
/// this binary's allocator, then by SQLite's, which keeps its own count (its pages, its sorts).
pub fn peak_during<T>(f: impl FnOnce() -> T) -> (T, usize, usize) {
    let base = HELD.load(Relaxed);
    PEAK.store(base, Relaxed);
    // SAFETY: SQLite reads and resets its memory counters under its own mutex, from any thread.
    let sqlite_base = unsafe { rusqlite::ffi::sqlite3_memory_used() };
    // SAFETY: as above; the reset makes the high-water mark what SQLite holds now.
    unsafe { rusqlite::ffi::sqlite3_memory_highwater(1) };
    let out = f();
    // SAFETY: as above.
    let sqlite_peak = unsafe { rusqlite::ffi::sqlite3_memory_highwater(0) };
    let held = PEAK.load(Relaxed).saturating_sub(base);
    let sqlite_held = usize::try_from(sqlite_peak - sqlite_base).unwrap_or(0);
    (out, held, sqlite_held)
}
