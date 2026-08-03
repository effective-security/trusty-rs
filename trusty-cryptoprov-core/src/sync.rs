//! Poison-tolerant lock helpers.
//!
//! A panic while holding one of these locks (the [`crate::registry::ProviderRegistry`],
//! or a provider crate's own key store) could in theory leave the guarded
//! state half-mutated. We accept that risk and recover the guard anyway,
//! rather than letting one thread's panic poison the lock for every other
//! caller — the guarded state here (a loader map, a key store) is only ever
//! fully replaced or inserted into as a whole, never partially built up
//! across multiple statements, so a half-applied mutation is not something
//! these particular locks can actually observe in practice.
//!
//! Public so provider crates (which own their own key-store mutexes, e.g.
//! `trusty-cryptoprov-inmem`) can reuse the same policy instead of
//! reimplementing it.

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// Lock `m`, recovering the guard even if a prior holder panicked.
pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Acquire `m` for reading, recovering the guard even if a prior holder panicked.
pub fn read<T>(m: &RwLock<T>) -> RwLockReadGuard<'_, T> {
    m.read().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Acquire `m` for writing, recovering the guard even if a prior holder panicked.
pub fn write<T>(m: &RwLock<T>) -> RwLockWriteGuard<'_, T> {
    m.write().unwrap_or_else(std::sync::PoisonError::into_inner)
}
