//! Keccak256 transcript matching `midnight_proofs::transcript::CircuitTranscript<Keccak256>`
//! byte-for-byte. The previous BN254-era implementation in this crate
//! used a different scheme (raw byte concatenation with a `0x01`
//! continuation marker, mod-r reduction of the 32-byte digest); this
//! file is a complete rewrite for the midnight-proofs migration.
//!
//! Reference Rust implementation:
//!   * `midfall/proofs/src/transcript/mod.rs::CircuitTranscript`
//!   * `midfall/proofs/src/transcript/implementors.rs::TranscriptHash for Keccak256`
//!
//! Behaviour summary:
//!
//!   * `init`: hasher = `Keccak256::new().update("Domain separator for transcript")`.
//!   * `common(input)`: hasher.update([1u8 PREFIX_COMMON]); hasher.update(input).
//!     For G1, `input` is the **EIP-2537 padded 128-byte uncompressed
//!     form** (`x_hi || x_lo || y_hi || y_lo`, 64 bytes per coord = 16
//!     zero pad bytes + 48 BE bytes of the BLS12-381 base-field
//!     element; identity = 128 zero bytes). This matches the patched
//!     `Hashable<Keccak256> for G1Projective::to_input` in
//!     `midnight-proofs` and lets the EVM verifier hash the calldata
//!     uncompressed bytes verbatim instead of running a 384-bit
//!     sign-bit ladder to derive the 48-byte compressed encoding.
//!     For Fq scalars, `input` is the canonical little-endian 32-byte
//!     repr (`Fq::to_repr()`).
//!   * `squeeze`: produces 64 bytes via two domain-separated finalisations
//!     (`state || PREFIX_CHALLENGE=0 || 0x00` and `... || 0x01`), then
//!     re-seeds the hasher with `Keccak256::new().update(out64)`.
//!   * `sample::<Fq>(out64)`: `Fq::from_uniform_bytes(&out64)` =
//!     `LE(out64[0..32]) + LE(out64[32..64]) * 2^256 (mod r)`.
//!
//! The Solidity verifier (`templates/Halo2Verifier.sol`) ports this exactly:
//! see Step 6 in MIGRATION.md for the planned Yul translation.

use std::io::{self, Cursor, Read, Write};

use ff::{FromUniformBytes, PrimeField};
use group::{prime::PrimeCurveAffine, GroupEncoding, UncompressedEncoding};
use midnight_curves::{Fq, G1Affine, G1Projective};
use sha3::{Digest, Keccak256};

/// Prefix matching `midnight_proofs::transcript::KECCAK256_PREFIX_CHALLENGE`.
pub(crate) const KECCAK256_PREFIX_CHALLENGE: u8 = 0;
/// Prefix matching `midnight_proofs::transcript::KECCAK256_PREFIX_COMMON`.
pub(crate) const KECCAK256_PREFIX_COMMON: u8 = 1;

/// In-memory Keccak256 transcript matching `CircuitTranscript<Keccak256>`.
#[derive(Clone, Debug)]
pub struct Keccak256Transcript<S> {
    state: Keccak256,
    stream: S,
}

impl<S: Default> Default for Keccak256Transcript<S> {
    fn default() -> Self {
        Self::new(S::default())
    }
}

impl<S> Keccak256Transcript<S> {
    /// Construct a new transcript wrapping `stream` with the midnight-
    /// proofs domain separator already absorbed.
    pub fn new(stream: S) -> Self {
        let mut state = Keccak256::new();
        state.update(b"Domain separator for transcript");
        Self { state, stream }
    }

    /// Absorb a `PREFIX_COMMON || input` block into the running hasher.
    fn absorb_bytes(&mut self, input: &[u8]) {
        self.state.update([KECCAK256_PREFIX_COMMON]);
        self.state.update(input);
    }

    /// Squeeze 64 bytes via the midnight-proofs two-fork pattern, then
    /// re-seed `self.state` with the squeezed bytes.
    fn squeeze_bytes(&mut self) -> [u8; 64] {
        // Append PREFIX_CHALLENGE inside the per-fork tag the same way
        // midnight-proofs' impl does (it absorbs PREFIX_CHALLENGE before
        // the fork tag).
        self.state.update([KECCAK256_PREFIX_CHALLENGE]);

        let mut h0 = self.state.clone();
        h0.update([0u8]);
        let out0 = h0.finalize();

        let mut h1 = self.state.clone();
        h1.update([1u8]);
        let out1 = h1.finalize();

        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&out0);
        out[32..].copy_from_slice(&out1);

        // Re-seed the state with the squeezed 64 bytes (matches Rust:
        // `state = Keccak256::new(); state.update(out)` -- importantly,
        // *no* domain separator is re-applied on reseed).
        let mut new_state = Keccak256::new();
        new_state.update(out);
        self.state = new_state;

        out
    }

    /// Squeeze a Fq challenge using `from_uniform_bytes` semantics.
    pub fn squeeze_challenge(&mut self) -> Fq {
        let bytes = self.squeeze_bytes();
        // Fq::from_uniform_bytes reduces 64 bytes (interpreted as a
        // 512-bit little-endian integer) modulo r.
        Fq::from_uniform_bytes(&bytes)
    }

    /// Absorb a Fq scalar in its canonical 32-byte LE repr.
    pub fn common_scalar(&mut self, scalar: &Fq) -> io::Result<()> {
        let repr = scalar.to_repr();
        self.absorb_bytes(repr.as_ref());
        Ok(())
    }

    /// Absorb a G1 point in its EIP-2537 padded 128-byte uncompressed
    /// form (matches the patched `Hashable<Keccak256> for
    /// G1Projective::to_input` in midnight-proofs).
    ///
    /// Layout: `x_hi (32) || x_lo (32) || y_hi (32) || y_lo (32)` where
    /// each coord is 16 zero pad bytes followed by 48 BE bytes of the
    /// base-field element. Identity = 128 zero bytes.
    pub fn common_g1(&mut self, point: &G1Projective) -> io::Result<()> {
        let bytes = g1_to_uncompressed_eip2537(point);
        self.absorb_bytes(&bytes);
        Ok(())
    }
}

/// Encode a `G1Projective` as the 128-byte EIP-2537 padded uncompressed
/// form used by the Fiat-Shamir transcript and the EVM verifier
/// calldata. Mirrors `Hashable<Keccak256> for G1Projective::to_input`
/// in midnight-proofs.
fn g1_to_uncompressed_eip2537(point: &G1Projective) -> [u8; 128] {
    let aff = G1Affine::from(point);
    let mut out = [0u8; 128];
    if !bool::from(aff.is_identity()) {
        let raw = <G1Affine as UncompressedEncoding>::to_uncompressed(&aff);
        let bytes: &[u8] = raw.as_ref();
        out[16..64].copy_from_slice(&bytes[0..48]);
        out[80..128].copy_from_slice(&bytes[48..96]);
    }
    out
}

impl<R: Read> Keccak256Transcript<R> {
    /// Read 32 bytes from the stream, absorb them via PREFIX_COMMON, and
    /// decode the canonical-LE Fq scalar.
    pub fn read_scalar(&mut self) -> io::Result<Fq> {
        let mut bytes = [0u8; 32];
        self.stream.read_exact(&mut bytes)?;
        self.absorb_bytes(&bytes);
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        Option::from(Fq::from_repr(repr))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Fq scalar"))
    }

    /// Read a 48-byte compressed G1 point from the stream, absorb the
    /// raw compressed bytes via PREFIX_COMMON, and decompress to
    /// `G1Projective`.
    pub fn read_g1(&mut self) -> io::Result<G1Projective> {
        let mut bytes = <G1Projective as GroupEncoding>::Repr::default();
        self.stream.read_exact(bytes.as_mut())?;
        self.absorb_bytes(bytes.as_ref());
        Option::from(G1Projective::from_bytes(&bytes)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid compressed BLS12-381 G1 point",
            )
        })
    }
}

impl Keccak256Transcript<Cursor<Vec<u8>>> {
    /// Initialise a transcript from raw proof bytes for verification.
    pub fn init_from_bytes(bytes: &[u8]) -> Self {
        Self::new(Cursor::new(bytes.to_vec()))
    }
}

impl<W: Write> Keccak256Transcript<W> {
    /// Append a Fq scalar to the proof stream and absorb it into the
    /// transcript.
    pub fn write_scalar(&mut self, scalar: &Fq) -> io::Result<()> {
        self.common_scalar(scalar)?;
        self.stream.write_all(scalar.to_repr().as_ref())
    }

    /// Append a G1 point (compressed) to the proof stream and absorb
    /// the compressed bytes into the transcript.
    pub fn write_g1(&mut self, point: &G1Projective) -> io::Result<()> {
        self.common_g1(point)?;
        let repr = <G1Projective as GroupEncoding>::to_bytes(point);
        self.stream.write_all(repr.as_ref())
    }

    /// Consume the transcript and return the underlying writer.
    pub fn finalize(self) -> W {
        self.stream
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use midnight_proofs::transcript::{CircuitTranscript, Transcript};
    use sha3::Keccak256;

    use super::*;

    /// Round-trip equivalence test against `midnight_proofs::transcript::CircuitTranscript<Keccak256>`.
    /// Squeeze a challenge from an empty transcript on both sides; the
    /// 64-byte intermediate hash and the resulting Fq sample must agree.
    #[test]
    fn empty_squeeze_matches_midnight_proofs() {
        let mut ours = Keccak256Transcript::new(Cursor::new(Vec::<u8>::new()));
        let theirs = {
            let mut t: CircuitTranscript<Keccak256> = CircuitTranscript::init();
            // Squeeze an Fq directly; no absorbs.
            let c: Fq = t.squeeze_challenge();
            c
        };
        let our_c = ours.squeeze_challenge();
        assert_eq!(our_c, theirs, "empty squeeze diverges");
    }

    #[test]
    fn common_scalar_then_squeeze_matches() {
        let s = Fq::from(0x1234567890abcdefu64);
        let mut ours = Keccak256Transcript::new(Cursor::new(Vec::<u8>::new()));
        ours.common_scalar(&s).unwrap();
        let our_c = ours.squeeze_challenge();

        let theirs = {
            let mut t: CircuitTranscript<Keccak256> = CircuitTranscript::init();
            t.common(&s).unwrap();
            let c: Fq = t.squeeze_challenge();
            c
        };

        assert_eq!(our_c, theirs);
    }

    #[test]
    fn common_g1_then_squeeze_matches() {
        use group::Group;
        let p = G1Projective::generator() * Fq::from(7u64);
        let mut ours = Keccak256Transcript::new(Cursor::new(Vec::<u8>::new()));
        ours.common_g1(&p).unwrap();
        let our_c = ours.squeeze_challenge();

        let theirs = {
            let mut t: CircuitTranscript<Keccak256> = CircuitTranscript::init();
            t.common(&p).unwrap();
            let c: Fq = t.squeeze_challenge();
            c
        };

        assert_eq!(our_c, theirs);
    }
}
