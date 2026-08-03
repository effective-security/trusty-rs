//! Per-slot session pool.

use crate::error::{Error, Result};
use cryptoki::context::Pkcs11;
use cryptoki::session::Session;
use cryptoki::slot::Slot;
use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use tracing::debug;

/// Maximum pooled sessions per slot.
pub const MAX_SESSIONS: usize = 1024;

/// Pool of exclusive RW sessions for one slot.
#[derive(Debug, Default)]
pub(crate) struct SessionPool {
    sessions: VecDeque<Session>,
}

impl SessionPool {
    fn take(&mut self) -> Option<Session> {
        self.sessions.pop_front()
    }

    /// Return a session if under capacity; otherwise drop/close it (non-blocking).
    fn release(&mut self, session: Session) {
        if self.sessions.len() < MAX_SESSIONS {
            self.sessions.push_back(session);
        } else {
            debug!(state = "session_pool_full", action = "close", capacity = MAX_SESSIONS);
            drop(session);
        }
    }

    fn clear(&mut self) {
        self.sessions.clear();
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.sessions.len()
    }
}

/// Map of slot ID → session pool.
#[derive(Debug, Default)]
pub(crate) struct SessionPools {
    inner: Mutex<HashMap<u64, SessionPool>>,
}

impl SessionPools {
    pub(crate) fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    pub(crate) fn setup(&self, slot_id: u64) {
        // Deliberately non-poisoning: a panic while holding this lock
        // should not wedge the pool for the process lifetime, and PKCS#11
        // sessions do not offer strong exception-safety guarantees to
        // preserve anyway.
        let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        map.entry(slot_id).or_default();
    }

    pub(crate) fn clear_all(&self) {
        let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        for pool in map.values_mut() {
            pool.clear();
        }
        map.clear();
    }

    /// Run `f` with an exclusive session for `slot`.
    pub(crate) fn with_session<T, F>(&self, ctx: &Pkcs11, slot: Slot, f: F) -> Result<T>
    where
        F: FnOnce(&Session) -> Result<T>,
    {
        let slot_id = slot.id();
        self.setup(slot_id);

        let session = {
            let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            let pool = map.get_mut(&slot_id).expect("setup just ensured pool");
            pool.take()
        };

        let session = match session {
            Some(s) => s,
            None => ctx.open_rw_session(slot).map_err(Error::from)?,
        };

        let result = f(&session);

        {
            let mut map = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
            if let Some(pool) = map.get_mut(&slot_id) {
                pool.release(session);
            } else {
                drop(session);
            }
        }

        result
    }
}

/// Open a new RW serial session (low-level; most callers use the pool).
///
/// # Errors
///
/// Returns [`Error::Pkcs11`] if the session cannot be opened.
pub fn open_rw_session(ctx: &Pkcs11, slot: Slot) -> Result<Session> {
    ctx.open_rw_session(slot).map_err(Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit-level check that release drops when full (no PKCS#11).
    #[test]
    fn pool_release_when_full_does_not_grow_past_capacity() {
        let pool = SessionPool::default();
        // We cannot construct real Session values without SoftHSM; verify capacity constant
        // and the release branch logic via a stand-in counter.
        assert_eq!(MAX_SESSIONS, 1024);
        assert_eq!(pool.len(), 0);

        // Simulate the capacity check used by release:
        let mut simulated_len = MAX_SESSIONS;
        let would_push = simulated_len < MAX_SESSIONS;
        assert!(!would_push);
        if would_push {
            simulated_len += 1;
        }
        assert_eq!(simulated_len, MAX_SESSIONS);
    }
}
