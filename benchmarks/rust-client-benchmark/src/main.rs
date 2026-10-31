use murmur_rust_client::{Client, Statement};
use std::env;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SEED_ROWS: u64 = 50_000;
const SECONDS: u64 = 15;

fn usage() {
    eprintln!("Usage: rust-client-benchmark [--seconds=N] [--seed-rows=N] [--batch-size=1|100] [--database=DIR]");
}
fn tree_bytes(path: &Path) -> u64 {
    let Ok(entries) = fs::read_dir(path) else { return 0 };
    entries.flatten().map(|entry| {
        let path = entry.path();
        if path.is_dir() { tree_bytes(&path) }
        else { entry.metadata().map(|m| m.len()).unwrap_or(0) }
    }).sum()
}
fn parse() -> Result<(u64, u64, u64, Option<PathBuf>), Box<dyn Error>> {
    let (mut seconds, mut seed, mut batch, mut path) = (SECONDS, SEED_ROWS, 1, None);
    for arg in env::args().skip(1) {
        if let Some(v) = arg.strip_prefix("--seconds=") { seconds = v.parse()?; }
        else if let Some(v) = arg.strip_prefix("--seed-rows=") { seed = v.parse()?; }
        else if let Some(v) = arg.strip_prefix("--batch-size=") { batch = v.parse()?; }
        else if let Some(v) = arg.strip_prefix("--database=") { path = Some(PathBuf::from(v)); }
        else { usage(); return Err(format!("unknown option {arg}").into()); }
    }
    if seconds == 0 || seed == 0 || ![1, 100].contains(&batch) {
        usage(); return Err("invalid numeric option".into());
    }
    Ok((seconds, seed, batch, path))
}
fn insert(stmt: &mut Statement<'_>, id: u64) -> Result<(), Box<dyn Error>> {
    stmt.bind_i64(1, id as i64)?;
    stmt.bind_payload(2)?;
    stmt.step()?;
    stmt.reset();
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    let (seconds, seed, batch, path) = parse()?;
    let path = path.unwrap_or_else(|| {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        env::temp_dir().join(format!("murmur-rust-bench-{}-{stamp}", std::process::id()))
    });
    fs::create_dir_all(&path)?;
    let path_text = path.to_str().ok_or("database path is not UTF-8")?;
    let db = Client::open(path_text)?;
    db.exec("CREATE TABLE records(id INTEGER PRIMARY KEY NOT NULL, body TEXT NOT NULL DEFAULT '');
      CREATE TABLE murmur_config(name TEXT PRIMARY KEY,value TEXT NOT NULL);
      CREATE TABLE murmur_identity(id INTEGER PRIMARY KEY CHECK(id=1),node BLOB,site BLOB,incarnation INTEGER NOT NULL DEFAULT 0);
      INSERT OR IGNORE INTO murmur_identity(id) VALUES(1);
      CREATE TABLE murmur_progress(node BLOB PRIMARY KEY,site BLOB NOT NULL,cursor BLOB NOT NULL,sent BLOB);
      CREATE TABLE murmur_excluded(node BLOB PRIMARY KEY);
      CREATE TABLE murmur_stage(node BLOB NOT NULL,idx INTEGER NOT NULL,data BLOB NOT NULL,created INTEGER NOT NULL,PRIMARY KEY(node,idx));
      CREATE TABLE murmur_kv(key BLOB PRIMARY KEY,value BLOB NOT NULL);
      CREATE TABLE murmur_file_chunks(digest BLOB NOT NULL,generation INTEGER NOT NULL,idx INTEGER NOT NULL,bytes BLOB NOT NULL,created_ms INTEGER NOT NULL,PRIMARY KEY(digest,generation,idx));
      CREATE TABLE murmur_file_transfers(transfer BLOB PRIMARY KEY,digest BLOB,generation INTEGER,total_bytes INTEGER,identity BLOB,created_ms INTEGER NOT NULL,updated_ms INTEGER NOT NULL);
      CREATE TABLE murmur_file_staging(transfer BLOB NOT NULL,idx INTEGER NOT NULL,bytes BLOB NOT NULL,created_ms INTEGER NOT NULL,PRIMARY KEY(transfer,idx));")?;
    {
        let mut seed_insert = db.prepare("INSERT INTO records(id,body) VALUES(?1,?2)")?;
        for id in 1..=seed { insert(&mut seed_insert, id)?; }
    }
    db.exec("SELECT crsql_as_crr('main','records')")?;
    let seed_version = db.scalar_i64("SELECT crsql_db_version()")?;
    let mut insert_stmt = db.prepare("INSERT INTO records(id,body) VALUES(?1,?2)")?;
    let mut read_stmt = db.prepare("SELECT body FROM records WHERE id=?1")?;
    let mut writes = 0u64;
    let mut transactions = 0u64;
    let mut rng = 1234u64.wrapping_mul(0x9e3779b97f4a7c15);
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(seconds) {
        if batch > 1 { db.exec("BEGIN IMMEDIATE")?; }
        for _ in 0..batch {
            writes += 1;
            insert(&mut insert_stmt, seed + writes)?;
            for _ in 0..4 {
                rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
                read_stmt.bind_i64(1, (rng % seed + 1) as i64)?;
                if read_stmt.step()? != 100 || !read_stmt.text_is_present() {
                    return Err("read did not return a row".into());
                }
                read_stmt.reset();
            }
        }
        if batch > 1 { db.exec("COMMIT")?; }
        transactions += 1;
    }
    let elapsed = start.elapsed().as_secs_f64();
    drop(insert_stmt); drop(read_stmt);
    let tracked = db.scalar_i64(&format!("SELECT count(*) FROM crsql_changes WHERE \"table\"='records' AND cid='body' AND db_version > {seed_version}"))? as u64;
    if tracked != writes { return Err(format!("tracked changes mismatch: {tracked} != {writes}").into()); }
    let raw_bytes = db.scalar_i64("PRAGMA page_count")? as u64 * db.scalar_i64("PRAGMA page_size")? as u64;
    drop(db);
    let disk_bytes = tree_bytes(&path);
    let disk_pct = if raw_bytes == 0 { 0.0 } else { disk_bytes as f64 * 100.0 / raw_bytes as f64 };
    println!("seconds,writes,transactions,ops_per_second,write_ops_per_second,tracked_changes,batch_size,read_write_mix,encryption,cipher,compression,replication,replication_crdt,raw_database_bytes,store_disk_bytes,disk_to_raw_pct");
    println!("{elapsed:.6},{writes},{transactions},{:.3},{:.3},{tracked},{batch},80_read_20_write,on,aegis256,zstd3,on,cr_sqlite_crdt,{raw_bytes},{disk_bytes},{disk_pct:.2}", writes as f64 * 5.0 / elapsed, writes as f64 / elapsed);
    Ok(())
}
