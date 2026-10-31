//! Small Rust client over the public libmurmur C ABI.
//! This crate intentionally has no third-party dependencies.
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::{c_char, c_int, c_void};
use std::marker::PhantomData;
use std::ptr;

#[repr(C)]
pub struct Sqlite3 { _private: [u8; 0] }
#[repr(C)]
pub struct Sqlite3Stmt { _private: [u8; 0] }

#[link(name = "murmur", kind = "static")]
extern "C" {
    fn murmur_init() -> c_int;
    fn murmur_vfs_register(cache_pages: c_int, flush_interval_ms: u32) -> c_int;
    fn murmur_db_key(db: *mut Sqlite3, key: *const u8) -> c_int;
    fn murmur_crsqlite_init(db: *mut Sqlite3) -> c_int;
    fn sqlite3_open_v2(path: *const c_char, db: *mut *mut Sqlite3, flags: c_int, vfs: *const c_char) -> c_int;
    fn sqlite3_close(db: *mut Sqlite3) -> c_int;
    fn sqlite3_errmsg(db: *mut Sqlite3) -> *const c_char;
    fn sqlite3_exec(db: *mut Sqlite3, sql: *const c_char,
        callback: Option<unsafe extern "C" fn(*mut c_void, c_int, *mut *mut c_char, *mut *mut c_char) -> c_int>,
        arg: *mut c_void, error: *mut *mut c_char) -> c_int;
    fn sqlite3_free(ptr: *mut c_void);
    fn sqlite3_prepare_v2(db: *mut Sqlite3, sql: *const c_char, bytes: c_int,
        stmt: *mut *mut Sqlite3Stmt, tail: *mut *const c_char) -> c_int;
    fn sqlite3_step(stmt: *mut Sqlite3Stmt) -> c_int;
    fn sqlite3_reset(stmt: *mut Sqlite3Stmt) -> c_int;
    fn sqlite3_finalize(stmt: *mut Sqlite3Stmt) -> c_int;
    fn sqlite3_clear_bindings(stmt: *mut Sqlite3Stmt) -> c_int;
    fn sqlite3_bind_int64(stmt: *mut Sqlite3Stmt, index: c_int, value: i64) -> c_int;
    fn sqlite3_bind_text(stmt: *mut Sqlite3Stmt, index: c_int, value: *const c_char,
        bytes: c_int, destructor: Option<unsafe extern "C" fn(*mut c_void)>) -> c_int;
    fn sqlite3_column_int64(stmt: *mut Sqlite3Stmt, index: c_int) -> i64;
    fn sqlite3_column_text(stmt: *mut Sqlite3Stmt, index: c_int) -> *const u8;
}

const SQLITE_OK: c_int = 0;
const SQLITE_ROW: c_int = 100;
const SQLITE_DONE: c_int = 101;
const OPEN_FLAGS: c_int = 0x00000002 | 0x00000004;
const PAYLOAD: &[u8] = b"sqlite-murmur-benchmark-payload-abcdefghijklmnopqrstuvwxyz-0123456789\0";

#[derive(Debug)]
pub struct Error(String);
impl fmt::Display for Error { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) } }
impl std::error::Error for Error {}
fn error(db: *mut Sqlite3, op: &str, rc: c_int) -> Error {
    let detail = if db.is_null() { "".into() } else {
        unsafe { CStr::from_ptr(sqlite3_errmsg(db)).to_string_lossy().into_owned() }
    };
    Error(format!("{op}: {detail} (SQLite rc {rc})"))
}
fn check(db: *mut Sqlite3, op: &str, rc: c_int) -> Result<(), Error> {
    if rc == SQLITE_OK { Ok(()) } else { Err(error(db, op, rc)) }
}

/// A connection to the Murmur VFS. The deterministic key is for benchmark
/// data only; applications should provision their own key securely.
pub struct Client { db: *mut Sqlite3 }
impl Client {
    pub fn open(path: &str) -> Result<Self, Error> {
        let path = CString::new(path).map_err(|e| Error(e.to_string()))?;
        unsafe {
            check(ptr::null_mut(), "murmur_init", murmur_init())?;
            check(ptr::null_mut(), "murmur_vfs_register", murmur_vfs_register(16384, 100))?;
            let mut db = ptr::null_mut();
            let rc = sqlite3_open_v2(path.as_ptr(), &mut db, OPEN_FLAGS, c"sqlite-murmur".as_ptr());
            check(db, "sqlite3_open_v2", rc)?;
            let key: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(17).wrapping_add(3));
            if let Err(e) = check(db, "murmur_db_key", murmur_db_key(db, key.as_ptr())) {
                sqlite3_close(db); return Err(e);
            }
            let client = Self { db };
            client.exec("PRAGMA cipher='aegis256'; PRAGMA compression='zstd3'; PRAGMA flush_interval_ms=100;")?;
            check(db, "murmur_crsqlite_init", murmur_crsqlite_init(db))?;
            Ok(client)
        }
    }
    pub fn exec(&self, sql: &str) -> Result<(), Error> {
        let sql = CString::new(sql).map_err(|e| Error(e.to_string()))?;
        unsafe {
            let mut err = ptr::null_mut();
            let rc = sqlite3_exec(self.db, sql.as_ptr(), None, ptr::null_mut(), &mut err);
            if rc == SQLITE_OK { return Ok(()); }
            let detail = if err.is_null() { String::new() } else {
                let s = CStr::from_ptr(err).to_string_lossy().into_owned(); sqlite3_free(err.cast()); s
            };
            Err(Error(format!("sqlite3_exec: {detail} (SQLite rc {rc})")))
        }
    }
    pub fn prepare(&self, sql: &str) -> Result<Statement<'_>, Error> {
        let sql = CString::new(sql).map_err(|e| Error(e.to_string()))?;
        unsafe {
            let mut stmt = ptr::null_mut();
            let rc = sqlite3_prepare_v2(self.db, sql.as_ptr(), -1, &mut stmt, ptr::null_mut());
            check(self.db, "sqlite3_prepare_v2", rc)?;
            Ok(Statement { db: self.db, stmt, _owner: PhantomData })
        }
    }
    pub fn scalar_i64(&self, sql: &str) -> Result<i64, Error> {
        let mut stmt = self.prepare(sql)?;
        if stmt.step()? != SQLITE_ROW { return Err(Error(format!("no row for {sql}"))); }
        Ok(unsafe { sqlite3_column_int64(stmt.stmt, 0) })
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        unsafe {
            let sql = b"SELECT crsql_finalize()\0";
            sqlite3_exec(self.db, sql.as_ptr().cast(), None, ptr::null_mut(), ptr::null_mut());
            sqlite3_close(self.db);
        }
    }
}

pub struct Statement<'db> { db: *mut Sqlite3, stmt: *mut Sqlite3Stmt, _owner: PhantomData<&'db Client> }
impl Statement<'_> {
    pub fn bind_i64(&mut self, index: i32, value: i64) -> Result<(), Error> {
        unsafe { check(self.db, "sqlite3_bind_int64", sqlite3_bind_int64(self.stmt, index, value)) }
    }
    pub fn bind_payload(&mut self, index: i32) -> Result<(), Error> {
        unsafe { check(self.db, "sqlite3_bind_text", sqlite3_bind_text(self.stmt, index,
            PAYLOAD.as_ptr().cast(), (PAYLOAD.len() - 1) as c_int, None)) }
    }
    pub fn step(&mut self) -> Result<c_int, Error> {
        unsafe { let rc = sqlite3_step(self.stmt); if rc == SQLITE_ROW || rc == SQLITE_DONE { Ok(rc) } else { Err(error(self.db, "sqlite3_step", rc)) } }
    }
    pub fn reset(&mut self) {
        unsafe { sqlite3_reset(self.stmt); sqlite3_clear_bindings(self.stmt); }
    }
    pub fn text_is_present(&self) -> bool { unsafe { !sqlite3_column_text(self.stmt, 0).is_null() } }
}
impl Drop for Statement<'_> { fn drop(&mut self) { unsafe { sqlite3_finalize(self.stmt); } } }
