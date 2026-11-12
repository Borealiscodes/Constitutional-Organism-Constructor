#![no_std]

use core::marker::PhantomData;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

pub struct Dormant;
pub struct Consented;

#[derive(Debug, PartialEq, Eq)]
pub enum SovereigntyError {
    InvalidSignature,
    ArtifactHashMismatch,
    TokenExpired,
    ScopeNotPermitted,
}

/// Signed capability token issued exclusively by the sovereign maintainer.
pub struct ConsentCapability<'a> {
    pub artifact_sha256: [u8; 32],
    pub expires_at_unix: u64,
    pub allow_rendering: bool,
    pub signature: &'a Signature,
}

/// Zero-cost type-state wrapper: `Dormant` organisms cannot execute or render.
pub struct ConstitutionalOrganism<T, State = Dormant> {
    payload: T,
    artifact_sha256: [u8; 32],
    _state: PhantomData<State>,
}

impl<T> ConstitutionalOrganism<T, Dormant> {
    /// Default constructor: always initializes in sealed `Dormant` state.
    pub const fn new_dormant(payload: T, artifact_sha256: [u8; 32]) -> Self {
        Self {
            payload,
            artifact_sha256,
            _state: PhantomData,
        }
    }

    /// Transitions `Dormant -> Consented` only if Ed25519 signature, digest,
    /// expiration, and explicit scope checks all succeed.
    pub fn activate_with_consent(
        self,
        author_pubkey: &VerifyingKey,
        cap: &ConsentCapability<'_>,
        now_unix: u64,
        signed_message_bytes: &[u8],
    ) -> Result<ConstitutionalOrganism<T, Consented>, SovereigntyError> {
        if cap.artifact_sha256 != self.artifact_sha256 {
            return Err(SovereigntyError::ArtifactHashMismatch);
        }
        if now_unix > cap.expires_at_unix {
            return Err(SovereigntyError::TokenExpired);
        }
        if !cap.allow_rendering {
            return Err(SovereigntyError::ScopeNotPermitted);
        }

        author_pubkey
            .verify(signed_message_bytes, cap.signature)
            .map_err(|_| SovereigntyError::InvalidSignature)?;

        Ok(ConstitutionalOrganism {
            payload: self.payload,
            artifact_sha256: self.artifact_sha256,
            _state: PhantomData,
        })
    }
}

impl<T> ConstitutionalOrganism<T, Consented> {
    /// Methods on `Consented` are unreachable at compile time while `Dormant`.
    pub fn inner(&self) -> &T {
        &self.payload
    }

    /// Unconditional, zero-cost return to `Dormant` state at any time.
    pub fn revoke_consent(self) -> ConstitutionalOrganism<T, Dormant> {
        ConstitutionalOrganism {
            payload: self.payload,
            artifact_sha256: self.artifact_sha256,
            _state: PhantomData,
        }
    }
}
