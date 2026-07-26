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

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LedgerError {
    #[error("ledger I/O failure")]
    Io,
    #[error("ledger contains invalid state")]
    Read,
    #[error("daily budget exceeded")]
    BudgetExceeded,
    #[error("reservation is not pending")]
    ReservationState,
    #[error("payment challenge already has retained counting state")]
    DuplicatePayment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerMutationOutcome {
    AppliedDurably,
    AppliedWithDurabilityWarning,
    NotApplied(LedgerError),
}
#[derive(Clone, Serialize, Deserialize)]
struct Entry {
    committed_sats: u64,
    reservations: BTreeMap<String, u64>,
}
#[derive(Clone, Debug)]
pub struct DailySpendLedger {
    pub path: PathBuf,
    write_fault: std::sync::Arc<std::sync::atomic::AtomicU8>,
}
#[doc(hidden)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LedgerWriteFault {
    None,
    BeforeRename,
    AfterRename,
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
            write_fault: std::sync::Arc::new(std::sync::atomic::AtomicU8::new(
                LedgerWriteFault::None as u8,
            )),
        }
    }
    #[doc(hidden)]
    pub fn set_write_fault_for_tests(&self, fault: LedgerWriteFault) {
        self.write_fault.store(fault as u8, Ordering::SeqCst);
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

    /// Reserve with a deterministic, non-secret challenge guard. A retained
    /// reservation makes a restart fail closed instead of paying the same
    /// challenge twice after an ambiguous submission or cache persistence
    /// failure.
    pub fn reserve_guarded(
        &self,
        amount_sats: u64,
        daily_budget_sats: u64,
        request_scope: &str,
        payment_hash: &[u8; 32],
    ) -> Result<LedgerReservation, LedgerError> {
        use sha2::{Digest, Sha256};
        let day = today();
        let mut digest = Sha256::new();
        digest.update(request_scope.as_bytes());
        digest.update([0]);
        digest.update(payment_hash);
        let id = format!("guard-{}", hex::encode(digest.finalize()));
        self.locked(|state| {
            let entry = state.entry(day.clone()).or_insert_with(empty);
            if entry.reservations.contains_key(&id) {
                return Err(LedgerError::DuplicatePayment);
            }
            let total = entry
                .committed_sats
                .checked_add(reservation_total(entry)?)
                .ok_or(LedgerError::Read)?;
            if total.checked_add(amount_sats).ok_or(LedgerError::Read)? > daily_budget_sats {
                return Err(LedgerError::BudgetExceeded);
            }
            entry.reservations.insert(id.clone(), amount_sats);
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
    /// Amount currently counting against today's limit, including fail-closed
    /// reservations retained across restarts.
    pub fn counting_today(&self) -> Result<u64, LedgerError> {
        self.locked(|state| {
            let Some(entry) = state.get(&today()) else {
                return Ok(0);
            };
            entry
                .committed_sats
                .checked_add(reservation_total(entry)?)
                .ok_or(LedgerError::Read)
        })
    }
    pub fn spent_on(&self, day: &str) -> Result<u64, LedgerError> {
        self.locked(|s| Ok(s.get(day).map(|e| e.committed_sats).unwrap_or(0)))
    }
    fn finish_classified(&self, id: &str, day: &str, commit: bool) -> LedgerMutationOutcome {
        self.locked_classified(|s| {
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
            match self.write_classified(&s) {
                LedgerMutationOutcome::AppliedDurably
                | LedgerMutationOutcome::AppliedWithDurabilityWarning => {}
                LedgerMutationOutcome::NotApplied(error) => return Err(error),
            }
        };
        let _ = FileExt::unlock(&file);
        r
    }
    fn locked_classified(
        &self,
        f: impl FnOnce(&mut BTreeMap<String, Entry>) -> Result<(), LedgerError>,
    ) -> LedgerMutationOutcome {
        let lock = self.path.with_extension(format!(
            "{}lock",
            self.path
                .extension()
                .and_then(|v| v.to_str())
                .map(|v| format!("{v}."))
                .unwrap_or_default()
        ));
        let Some(parent) = lock.parent() else {
            return LedgerMutationOutcome::NotApplied(LedgerError::Io);
        };
        if fs::create_dir_all(parent).is_err() {
            return LedgerMutationOutcome::NotApplied(LedgerError::Io);
        }
        let file = match safe_open(&lock, true) {
            Ok(value) => value,
            Err(error) => return LedgerMutationOutcome::NotApplied(error),
        };
        if FileExt::lock(&file).is_err() {
            return LedgerMutationOutcome::NotApplied(LedgerError::Io);
        }
        let mut state = match self.read() {
            Ok(value) => value,
            Err(error) => {
                let _ = FileExt::unlock(&file);
                return LedgerMutationOutcome::NotApplied(error);
            }
        };
        if let Err(error) = f(&mut state) {
            let _ = FileExt::unlock(&file);
            return LedgerMutationOutcome::NotApplied(error);
        }
        let outcome = self.write_classified(&state);
        let _ = FileExt::unlock(&file);
        outcome
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
    fn write_classified(&self, state: &BTreeMap<String, Entry>) -> LedgerMutationOutcome {
        let mut bytes = match serde_json::to_vec(state) {
            Ok(value) => value,
            Err(_) => return LedgerMutationOutcome::NotApplied(LedgerError::Read),
        };
        bytes.push(b'\n');
        let parent = self.path.parent().unwrap_or(Path::new("."));
        if fs::create_dir_all(parent).is_err() {
            return LedgerMutationOutcome::NotApplied(LedgerError::Io);
        }
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
        let before_rename = (|| {
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
            if self.write_fault.load(Ordering::SeqCst) == LedgerWriteFault::BeforeRename as u8 {
                return Err(LedgerError::Io);
            }
            fs::rename(&tmp, &self.path).map_err(|_| LedgerError::Io)
        })();
        if let Err(error) = before_rename {
            let _ = fs::remove_file(&tmp);
            return LedgerMutationOutcome::NotApplied(error);
        }
        let mut warning =
            self.write_fault.load(Ordering::SeqCst) == LedgerWriteFault::AfterRename as u8;
        warning |= std::fs::File::open(parent)
            .and_then(|d| d.sync_all())
            .is_err();
        #[cfg(unix)]
        {
            warning |= fs::set_permissions(&self.path, fs::Permissions::from_mode(0o600)).is_err();
        }
        if warning {
            LedgerMutationOutcome::AppliedWithDurabilityWarning
        } else {
            LedgerMutationOutcome::AppliedDurably
        }
    }
}
impl LedgerReservation {
    pub fn id(&self) -> &str {
        &self.id
    }
    pub fn commit(&mut self) -> Result<(), LedgerError> {
        match self.commit_classified() {
            LedgerMutationOutcome::AppliedDurably
            | LedgerMutationOutcome::AppliedWithDurabilityWarning => Ok(()),
            LedgerMutationOutcome::NotApplied(error) => Err(error),
        }
    }
    pub fn commit_classified(&mut self) -> LedgerMutationOutcome {
        if self.state == ReservationState::Committed {
            return LedgerMutationOutcome::AppliedDurably;
        }
        if self.state == ReservationState::RolledBack {
            return LedgerMutationOutcome::NotApplied(LedgerError::ReservationState);
        }
        let outcome = self.ledger.finish_classified(&self.id, &self.day, true);
        if matches!(
            outcome,
            LedgerMutationOutcome::AppliedDurably
                | LedgerMutationOutcome::AppliedWithDurabilityWarning
        ) {
            self.state = ReservationState::Committed;
        }
        outcome
    }
    pub fn rollback(&mut self) -> Result<(), LedgerError> {
        match self.rollback_classified() {
            LedgerMutationOutcome::AppliedDurably
            | LedgerMutationOutcome::AppliedWithDurabilityWarning => Ok(()),
            LedgerMutationOutcome::NotApplied(error) => Err(error),
        }
    }
    pub fn rollback_classified(&mut self) -> LedgerMutationOutcome {
        if self.state == ReservationState::Committed || self.state == ReservationState::RolledBack {
            return LedgerMutationOutcome::AppliedDurably;
        }
        let outcome = self.ledger.finish_classified(&self.id, &self.day, false);
        if matches!(
            outcome,
            LedgerMutationOutcome::AppliedDurably
                | LedgerMutationOutcome::AppliedWithDurabilityWarning
        ) {
            self.state = ReservationState::RolledBack;
        }
        outcome
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
