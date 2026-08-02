//! Hardware RNG via PKCS#11 `C_GenerateRandom`.

use crate::Pkcs11Lib;
use crate::error::{Error, Result};

impl Pkcs11Lib {
    /// Fill `data` with random bytes from the token RNG on the current slot.
    ///
    /// Returns the number of bytes written (always `data.len()` on success).
    ///
    /// # Errors
    ///
    /// Returns [`Error::Closed`] if the library has been closed, or
    /// [`Error::Pkcs11`] if the token cannot generate random data.
    pub fn gen_random(&self, data: &mut [u8]) -> Result<usize> {
        let slot = self.inner.slot.slot()?;
        self.with_session(slot, |session| {
            session.generate_random_slice(data).map_err(Error::from)?;
            Ok(data.len())
        })
    }
}
