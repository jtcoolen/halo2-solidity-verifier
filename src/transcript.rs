//! Keccak256 transcript matching `midnight_proofs::transcript::CircuitTranscript<Keccak256>`
//! byte-for-byte. The previous BN254-era implementation in this crate
//! used a different scheme (raw byte concatenation with a `0x01`
//! continuation marker, mod-r reduction of a 32-byte digest); this file
//! follows the local Midfall `keccak` transcript used by the Solidity
//! verifier trace/bench tests.
//!
//! Reference Rust implementation:
//!   * `midfall/proofs/src/transcript/mod.rs::CircuitTranscript`
//!   * `midfall/proofs/src/transcript/implementors.rs::TranscriptHash for Keccak256`
//!   * `midfall/proofs/src/transcript/implementors.rs::Hashable<Keccak256> for G1Projective`
//!
//! Behaviour summary:
//!
//!   * `init`: Keccak state starts empty.
//!   * `common(input)`: absorb `input`.
//!     This ports the upstream `Transcript::common` comment path: typed
//!     verifier values are converted with `Hashable::to_input` before they are
//!     appended to the Fiat-Shamir state.
//!     For G1, `input` is the **EIP-2537 padded 128-byte uncompressed
//!     form** (`x_hi || x_lo || y_hi || y_lo`, 64 bytes per coord = 16
//!     zero pad bytes + 48 BE bytes of the BLS12-381 base-field
//!     element; identity = 128 zero bytes). This matches the published
//!     `Hashable<Keccak256> for G1Projective::to_input` in
//!     `midnight-proofs` and lets the EVM verifier hash the calldata
//!     uncompressed bytes verbatim instead of running a 384-bit
//!     sign-bit ladder to derive the 48-byte compressed encoding.
//!     For Fq scalars, `input` is the canonical big-endian 32-byte repr.
//!   * `squeeze`: produce one 32-byte Keccak digest over the current state,
//!     then reseed the Keccak state with that digest.
//!     This mirrors the Midfall comment that subsequent absorb/squeeze calls
//!     must depend on the challenge that was just produced.
//!   * `sample::<Fq>(out32)`: interpret the digest as a big-endian integer
//!     and reduce it modulo the scalar-field modulus.
//!
//! The Solidity verifier (`templates/Halo2Verifier.sol`) ports this exactly:
//! see Step 6 in MIGRATION.md for the planned Yul translation.

use std::io::{self, Cursor, Read, Write};

use ff::PrimeField;
use group::{prime::PrimeCurveAffine, GroupEncoding, UncompressedEncoding};
use midnight_curves::{Fq, G1Affine, G1Projective};
use ruint::aliases::U256;
use sha3::{Digest, Keccak256};

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
    /// Construct a new transcript wrapping `stream` with empty transcript
    /// data.
    pub fn new(stream: S) -> Self {
        let state = Keccak256::new();
        Self { state, stream }
    }

    /// Absorb input bytes into the running transcript data.
    fn absorb_bytes(&mut self, input: &[u8]) {
        self.state.update(input);
    }

    /// Squeeze one 32-byte output, then reset the transcript state to the
    /// squeezed output.
    fn squeeze_bytes(&mut self) -> [u8; 32] {
        let digest = self.state.clone().finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);

        let mut state = Keccak256::new();
        state.update(out);
        self.state = state;
        out
    }

    /// Squeeze a Fq challenge using BE digest modulo-r semantics.
    pub fn squeeze_challenge(&mut self) -> Fq {
        fq_from_be_digest_mod_r(self.squeeze_bytes())
    }

    /// Absorb a Fq scalar in its canonical 32-byte BE transcript repr.
    pub fn common_scalar(&mut self, scalar: &Fq) -> io::Result<()> {
        let mut repr = scalar.to_repr();
        repr.as_mut().reverse();
        self.absorb_bytes(repr.as_ref());
        Ok(())
    }

    /// Absorb a G1 point in its EIP-2537 padded 128-byte uncompressed
    /// form (matches the published `Hashable<Keccak256> for
    /// G1Projective::to_input` in midnight-proofs).
    ///
    /// Layout: `x_hi (32) || x_lo (32) || y_hi (32) || y_lo (32)` where
    /// each coord is 16 zero pad bytes followed by 48 BE bytes of the
    /// base-field element. Identity = 128 zero bytes.
    ///
    /// The upstream comment explains why this is verifier-friendly on EVM:
    /// the Solidity verifier can copy the four calldata words into the
    /// Keccak buffer after canonical padding/range checks, rather than
    /// deriving a compressed sign bit on chain.
    pub fn common_g1(&mut self, point: &G1Projective) -> io::Result<()> {
        let bytes = g1_to_uncompressed_eip2537(point);
        self.absorb_bytes(&bytes);
        Ok(())
    }
}

fn fq_from_be_digest_mod_r(digest: [u8; 32]) -> Fq {
    let modulus = U256::from_str_radix(Fq::MODULUS.trim_start_matches("0x"), 16)
        .expect("Fq::MODULUS must parse as hex");
    let reduced = U256::from_be_bytes(digest) % modulus;
    let bytes = reduced.to_le_bytes::<32>();

    let mut repr = <Fq as PrimeField>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    Option::from(Fq::from_repr(repr)).expect("reduced Keccak challenge must be canonical")
}

impl<R: Read> Keccak256Transcript<R> {
    /// Read a canonical Fq scalar from the stream, absorb its transcript
    /// representation, and decode it.
    pub fn read_scalar(&mut self) -> io::Result<Fq> {
        let mut bytes = [0u8; 32];
        self.stream.read_exact(&mut bytes)?;
        let mut repr = <Fq as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        let scalar = Option::from(Fq::from_repr(repr))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid Fq scalar"))?;
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    /// Read a 48-byte compressed G1 point from the stream, decompress it,
    /// and absorb its canonical EIP-2537 padded uncompressed transcript
    /// representation.
    pub fn read_g1(&mut self) -> io::Result<G1Projective> {
        let mut bytes = <G1Projective as GroupEncoding>::Repr::default();
        self.stream.read_exact(bytes.as_mut())?;
        let point = Option::from(G1Projective::from_bytes(&bytes)).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid compressed BLS12-381 G1 point",
            )
        })?;
        self.common_g1(&point)?;
        Ok(point)
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

    /// Append a G1 point in compressed proof encoding and absorb its
    /// canonical EIP-2537 padded uncompressed transcript representation.
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
    /// 32-byte intermediate hash and the resulting Fq sample must agree.
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

    #[test]
    fn read_g1_matches_write_g1_transcript_state() {
        use group::Group;

        for point in [
            G1Projective::identity(),
            G1Projective::generator() * Fq::from(7u64),
        ] {
            let mut writer = Keccak256Transcript::new(Cursor::new(Vec::<u8>::new()));
            writer.write_g1(&point).unwrap();
            let expected_challenge = writer.squeeze_challenge();
            let proof_bytes = writer.finalize().into_inner();

            let mut reader = Keccak256Transcript::new(Cursor::new(proof_bytes));
            let decoded = reader.read_g1().unwrap();
            let actual_challenge = reader.squeeze_challenge();

            assert_eq!(decoded, point);
            assert_eq!(actual_challenge, expected_challenge);
        }
    }
}
