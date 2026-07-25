//! Process-safe daily reservation ledger.
use fs4::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LedgerError {
    #[error("ledger I/O failure")]
    Io,
    #[error("ledger contains invalid state")]
    Read,
    #[error("daily budget exceeded")]
    BudgetExceeded,
    #[error("reservation is not pending")]
    ReservationState,
}
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    committed_sats: u64,
    reservations: BTreeMap<String, u64>,
}
#[derive(Clone, Debug)]
pub struct DailySpendLedger {
    pub path: PathBuf,
}
#[derive(Clone, Debug)]
pub struct LedgerReservation {
    ledger: DailySpendLedger,
    id: String,
    day: String,
    pub amount_sats: u64,
    state: ReservationState,
}
#[derive(Clone, Debug, PartialEq, Eq)]
enum ReservationState {
    Pending,
    Committed,
    RolledBack,
}
static COUNTER: AtomicU64 = AtomicU64::new(0);
impl DailySpendLedger {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: crate::config::expand_path(path.into()),
        }
    }
    pub fn default_path(namespace: Option<&str>) -> Result<PathBuf, LedgerError> {
        let n = crate::state::normalize_namespace(namespace).map_err(|_| LedgerError::Read)?;
        let base = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| crate::config::expand_path("~/.local/state"));
        let mut p = base.join("paygate-client");
        if n != "default" {
            p = p.join("profiles").join(n)
        };
        Ok(p.join("daily-spend-ledger.json"))
    }
    pub fn reserve(
        &self,
        amount_sats: u64,
        daily_budget_sats: u64,
    ) -> Result<LedgerReservation, LedgerError> {
        let day = today();
        let id = format!(
            "{:x}{:x}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        self.locked(|state| {
            let e = state.entry(day.clone()).or_insert_with(empty);
            let total = e
                .committed_sats
                .checked_add(reservation_total(e)?)
                .ok_or(LedgerError::Read)?;
            if total.checked_add(amount_sats).ok_or(LedgerError::Read)? > daily_budget_sats {
                return Err(LedgerError::BudgetExceeded);
            }
            e.reservations.insert(id.clone(), amount_sats);
            Ok(())
        })?;
        Ok(LedgerReservation {
            ledger: self.clone(),
            id,
            day,
            amount_sats,
            state: ReservationState::Pending,
        })
    }
    pub fn spent_today(&self) -> Result<u64, LedgerError> {
        self.spent_on(&today())
    }
    pub fn spent_on(&self, day: &str) -> Result<u64, LedgerError> {
        self.locked(|s| Ok(s.get(day).map(|e| e.committed_sats).unwrap_or(0)))
    }
    fn finish(&self, id: &str, day: &str, commit: bool) -> Result<(), LedgerError> {
        self.locked(|s| {
            let e = s.entry(day.into()).or_insert_with(empty);
            let v = e
                .reservations
                .remove(id)
                .ok_or(LedgerError::ReservationState)?;
            if commit {
                e.committed_sats = e.committed_sats.checked_add(v).ok_or(LedgerError::Read)?
            };
            Ok(())
        })
    }
    fn locked<T>(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, Entry>) -> Result<T, LedgerError>,
    ) -> Result<T, LedgerError> {
        let lock = self.path.with_extension(format!(
            "{}lock",
            self.path
                .extension()
                .and_then(|v| v.to_str())
                .map(|v| format!("{v}."))
                .unwrap_or_default()
        ));
        if let Some(p) = lock.parent() {
            fs::create_dir_all(p).map_err(|_| LedgerError::Io)?
        };
        let file = safe_open(&lock, true)?;
        FileExt::lock(&file).map_err(|_| LedgerError::Io)?;
        let mut s = self.read()?;
        let r = f(&mut s);
        if r.is_ok() {
            self.write(&s)?
        };
        let _ = FileExt::unlock(&file);
        r
    }
    fn read(&self) -> Result<BTreeMap<String, Entry>, LedgerError> {
        // Read only through a descriptor validated after opening; a separate
        // validate-then-read path is vulnerable to replacement races.
        let Some(mut state) = safe_open_read(&self.path)? else {
            return Ok(BTreeMap::new());
        };
        let mut bytes = Vec::new();
        state.read_to_end(&mut bytes).map_err(|_| LedgerError::Io)?;
        let s: BTreeMap<String, Entry> =
            serde_json::from_slice(&bytes).map_err(|_| LedgerError::Read)?;
        for e in s.values() {
            if e.committed_sats
                .checked_add(reservation_total(e)?)
                .is_none()
            {
                return Err(LedgerError::Read);
            }
        }
        Ok(s)
    }
    fn write(&self, state: &BTreeMap<String, Entry>) -> Result<(), LedgerError> {
        let mut bytes = serde_json::to_vec(state).map_err(|_| LedgerError::Read)?;
        bytes.push(b'\n');
        let parent = self.path.parent().unwrap_or(Path::new("."));
        fs::create_dir_all(parent).map_err(|_| LedgerError::Io)?;
        let tmp = parent.join(format!(
            ".{}.{}.{}.tmp",
            self.path
                .file_name()
                .and_then(|v| v.to_str())
                .unwrap_or("ledger"),
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let write = (|| {
            #[cfg(unix)]
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)
                .map_err(|_| LedgerError::Io)?;
            #[cfg(not(unix))]
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)
                .map_err(|_| LedgerError::Io)?;
            f.write_all(&bytes).map_err(|_| LedgerError::Io)?;
            f.sync_all().map_err(|_| LedgerError::Io)?;
            drop(f);
            fs::rename(&tmp, &self.path).map_err(|_| LedgerError::Io)?;
            std::fs::File::open(parent)
                .and_then(|d| d.sync_all())
                .map_err(|_| LedgerError::Io)
        })();
        if write.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        write?;
        #[cfg(unix)]
        fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600))
            .map_err(|_| LedgerError::Io)?;
        Ok(())
    }
}
impl LedgerReservation {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn commit(&mut self) -> Result<(), LedgerError> {
        if self.state == ReservationState::Committed {
            return Ok(());
        }
        if self.state == ReservationState::RolledBack {
            return Err(LedgerError::ReservationState);
        }
        self.ledger.finish(&self.id, &self.day, true)?;
        self.state = ReservationState::Committed;
        Ok(())
    }
    pub fn rollback(&mut self) -> Result<(), LedgerError> {
        if self.state == ReservationState::Committed || self.state == ReservationState::RolledBack {
            return Ok(());
        }
        self.ledger.finish(&self.id, &self.day, false)?;
        self.state = ReservationState::RolledBack;
        Ok(())
    }
}
fn empty() -> Entry {
    Entry {
        committed_sats: 0,
        reservations: BTreeMap::new(),
    }
}
fn reservation_total(entry: &Entry) -> Result<u64, LedgerError> {
    entry
        .reservations
        .values()
        .try_fold(0_u64, |total, amount| total.checked_add(*amount))
        .ok_or(LedgerError::Read)
}
fn today() -> String {
    #[cfg(unix)]
    {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as libc::time_t;
        // The Python ledger uses local `date.today()`, rather than UTC.
        let mut out: libc::tm = unsafe { std::mem::zeroed() };
        unsafe { libc::localtime_r(&seconds, &mut out) };
        return format!(
            "{:04}-{:02}-{:02}",
            out.tm_year + 1900,
            out.tm_mon + 1,
            out.tm_mday
        );
    }
    #[cfg(not(unix))]
    {
        "1970-01-01".into()
    }
}
fn safe_open(path: &Path, create: bool) -> Result<std::fs::File, LedgerError> {
    #[cfg(unix)]
    {
        if let Ok(m) = fs::symlink_metadata(path) {
            if m.file_type().is_symlink() || !m.file_type().is_file() {
                return Err(LedgerError::Io);
            }
        }
        let mut o = OpenOptions::new();
        o.read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW)
            .mode(0o600);
        if create {
            o.create(true);
        };
        let f = o.open(path).map_err(|_| LedgerError::Io)?;
        if f.metadata()
            .map_err(|_| LedgerError::Io)?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err(LedgerError::Io);
        };
        Ok(f)
    }
    #[cfg(not(unix))]
    {
        let _ = create;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(path)
            .map_err(|_| LedgerError::Io)
    }
}
fn safe_open_read(path: &Path) -> Result<Option<std::fs::File>, LedgerError> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(libc::O_NOFOLLOW);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(LedgerError::Io),
        };
        let metadata = file.metadata().map_err(|_| LedgerError::Io)?;
        if !metadata.file_type().is_file() || metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(LedgerError::Io);
        }
        Ok(Some(file))
    }
    #[cfg(not(unix))]
    {
        let file = match OpenOptions::new().read(true).open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(LedgerError::Io),
        };
        if !file
            .metadata()
            .map_err(|_| LedgerError::Io)?
            .file_type()
            .is_file()
        {
            return Err(LedgerError::Io);
        }
        Ok(Some(file))
    }
}
