//! A process's first opens, all at once. SQLite marks itself initialized, then runs SQLCipher's
//! own initialization (`SQLITE_EXTRA_INIT`) outside its mutex: an open in between found SQLCipher
//! not ready, and its key couldn't be set. Only a process's first opens can race, so this test
//! has a binary of its own, and must stay the only test in it.

use std::ffi::c_int;
use std::ptr;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize};
use std::sync::{Barrier, OnceLock};
use std::time::Duration;

use duvet_e2e::{Core, OpenConfig};
use rusqlite::ffi;

#[test]
fn first_opens_at_once_all_open() {
    pause_after_sqlites_initialization();
    let dirs: Vec<_> = (0..4).map(|_| tempfile::tempdir().unwrap()).collect();
    let start = Barrier::new(dirs.len());
    std::thread::scope(|scope| {
        let opens: Vec<_> = dirs
            .iter()
            .map(|dir| {
                let start = &start;
                scope.spawn(move || {
                    start.wait();
                    Core::open(OpenConfig::new(dir.path().join("core.db"), [1; 32]))
                        .map(Core::close)
                        .map_err(|error| error.to_string())
                })
            })
            .collect();
        for open in opens {
            assert_eq!(open.join().unwrap(), Ok(()));
        }
    });
    assert!(PAUSED.load(SeqCst), "SQLite's initialization never paused");
}

/// SQLite's own mutex methods, which the test's wrap.
struct Defaults(ffi::sqlite3_mutex_methods);
// SAFETY: function pointers, set once before SQLite takes the wrappers.
unsafe impl Send for Defaults {}
unsafe impl Sync for Defaults {}

static DEFAULTS: OnceLock<Defaults> = OnceLock::new();
/// SQLite's initialization mutex: the first recursive mutex, which `sqlite3_initialize` allocates.
static INIT_MUTEX: AtomicPtr<ffi::sqlite3_mutex> = AtomicPtr::new(ptr::null_mut());
/// How deep its holder has entered it.
static DEPTH: AtomicUsize = AtomicUsize::new(0);
static PAUSED: AtomicBool = AtomicBool::new(false);

fn defaults() -> &'static ffi::sqlite3_mutex_methods {
    &DEFAULTS.get().expect("the wrappers are installed").0
}

/// Wraps SQLite's mutexes so that the thread that initializes SQLite pauses where the race is:
/// right after it lets go of the initialization mutex, with SQLite marked initialized and
/// SQLCipher not yet.
fn pause_after_sqlites_initialization() {
    // SAFETY: nothing in this process has used SQLite yet, so its configuration can change.
    unsafe {
        // Allocating a static mutex fills in SQLite's own mutex methods without initializing it.
        assert!(!ffi::sqlite3_mutex_alloc(ffi::SQLITE_MUTEX_STATIC_MAIN).is_null());
        let mut methods: ffi::sqlite3_mutex_methods = std::mem::zeroed();
        let code = ffi::sqlite3_config(ffi::SQLITE_CONFIG_GETMUTEX, &raw mut methods);
        assert_eq!(code, ffi::SQLITE_OK);
        let wrapped = ffi::sqlite3_mutex_methods {
            xMutexAlloc: Some(alloc),
            xMutexFree: Some(free),
            xMutexEnter: Some(enter),
            xMutexTry: Some(try_enter),
            xMutexLeave: Some(leave),
            ..methods
        };
        assert!(DEFAULTS.set(Defaults(methods)).is_ok());
        let code = ffi::sqlite3_config(ffi::SQLITE_CONFIG_MUTEX, &raw const wrapped);
        assert_eq!(code, ffi::SQLITE_OK);
    }
}

unsafe extern "C" fn alloc(id: c_int) -> *mut ffi::sqlite3_mutex {
    let mutex = unsafe { defaults().xMutexAlloc.unwrap()(id) };
    if id == ffi::SQLITE_MUTEX_RECURSIVE {
        // Taken only while none is kept, so the first one stays.
        INIT_MUTEX
            .compare_exchange(ptr::null_mut(), mutex, SeqCst, SeqCst)
            .ok();
    }
    mutex
}

unsafe extern "C" fn free(mutex: *mut ffi::sqlite3_mutex) {
    INIT_MUTEX
        .compare_exchange(mutex, ptr::null_mut(), SeqCst, SeqCst)
        .ok();
    unsafe { defaults().xMutexFree.unwrap()(mutex) }
}

unsafe extern "C" fn enter(mutex: *mut ffi::sqlite3_mutex) {
    unsafe { defaults().xMutexEnter.unwrap()(mutex) };
    if mutex == INIT_MUTEX.load(SeqCst) {
        DEPTH.fetch_add(1, SeqCst);
    }
}

unsafe extern "C" fn try_enter(mutex: *mut ffi::sqlite3_mutex) -> c_int {
    let code = unsafe { defaults().xMutexTry.unwrap()(mutex) };
    if code == ffi::SQLITE_OK && mutex == INIT_MUTEX.load(SeqCst) {
        DEPTH.fetch_add(1, SeqCst);
    }
    code
}

unsafe extern "C" fn leave(mutex: *mut ffi::sqlite3_mutex) {
    let released = mutex == INIT_MUTEX.load(SeqCst) && DEPTH.fetch_sub(1, SeqCst) == 1;
    unsafe { defaults().xMutexLeave.unwrap()(mutex) };
    // The first whole release is the initializing thread's, right after SQLite marked itself
    // initialized and before SQLCipher's initialization: the race's window, held open.
    if released && !PAUSED.swap(true, SeqCst) {
        std::thread::sleep(Duration::from_millis(200));
    }
}
