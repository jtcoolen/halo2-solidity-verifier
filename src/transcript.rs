use halo2_proofs::{
    halo2curves::{ff::PrimeField, Coordinates, CurveAffine},
    transcript::{
        EncodedChallenge, Transcript, TranscriptRead, TranscriptReadBuffer, TranscriptWrite,
        TranscriptWriterBuffer,
    },
};
use itertools::{chain, Itertools};
use ruint::aliases::U256;
use sha3::{Digest, Keccak256};
use std::{
    io::{self, Read, Write},
    marker::PhantomData,
    mem,
};

/// Transcript using Keccak256 as hash function in Fiat-Shamir transformation.
#[derive(Debug, Default)]
pub struct Keccak256Transcript<C, S> {
    stream: S,
    buf: Vec<u8>,
    _marker: PhantomData<C>,
}

impl<C, S> Keccak256Transcript<C, S> {
    /// Return a `Keccak256Transcript` with empty buffer.
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            _marker: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct ChallengeEvm<C>(C::Scalar)
where
    C: CurveAffine,
    C::Scalar: PrimeField,
    <C::Scalar as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]>;

impl<C> EncodedChallenge<C> for ChallengeEvm<C>
where
    C: CurveAffine,
    C::Scalar: PrimeField,
    <C::Scalar as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]> + From<[u8; 0x20]>,
{
    type Input = [u8; 0x20];

    fn new(challenge_input: &[u8; 0x20]) -> Self {
        ChallengeEvm(u256_to_fe(U256::from_be_bytes(*challenge_input)))
    }

    fn get_scalar(&self) -> C::Scalar {
        self.0
    }
}

impl<C, S> Transcript<C, ChallengeEvm<C>> for Keccak256Transcript<C, S>
where
    C: CurveAffine,
    C::Scalar: PrimeField,
    <C::Scalar as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]> + From<[u8; 0x20]>,
    <C::Base as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]>,
{
    fn squeeze_challenge(&mut self) -> ChallengeEvm<C> {
        let buf_len = self.buf.len();
        let data = chain![
            mem::take(&mut self.buf),
            if buf_len == 0x20 { Some(1) } else { None }
        ]
        .collect_vec();
        let hash: [u8; 0x20] = Keccak256::digest(data).into();
        self.buf = hash.to_vec();
        ChallengeEvm::new(&hash)
    }

    fn common_point(&mut self, ec_point: C) -> io::Result<()> {
        let coords: Coordinates<C> = Option::from(ec_point.coordinates()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Other,
                "Invalid elliptic curve point".to_string(),
            )
        })?;
        // The Solidity verifier reads each G1 point as the EIP-2537 padded
        // 128-byte layout (`(x_hi | x_lo | y_hi | y_lo)`, 64 bytes per
        // coordinate, 16 zero bytes + 48 BLS Fp big-endian bytes per coord)
        // and hashes those bytes verbatim into the Fiat-Shamir transcript.
        // To make the prover's hash agree with the verifier's, we write
        // the same 64-byte-per-coord padded form here.
        //
        // halo2derive's `to_repr()` always returns little-endian bytes
        // regardless of the field's `endian =` setting, so we flip to
        // big-endian and then left-pad with 16 zero bytes so each coord
        // lands in the low bytes of an EIP-2537 64-byte slot.
        for coordinate in [coords.x(), coords.y()] {
            let repr = coordinate.to_repr();
            let bytes_be: Vec<u8> = repr.as_ref().iter().rev().copied().collect();
            assert!(
                bytes_be.len() <= 64,
                "common_point: coordinate repr ({} bytes) doesn't fit in EIP-2537 64-byte slot",
                bytes_be.len(),
            );
            let pad = 64 - bytes_be.len();
            self.buf.extend(std::iter::repeat(0u8).take(pad));
            self.buf.extend(bytes_be);
        }
        Ok(())
    }

    fn common_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        self.buf.extend(scalar.to_repr().as_ref().iter().rev());
        Ok(())
    }
}

impl<C, R: Read> TranscriptRead<C, ChallengeEvm<C>> for Keccak256Transcript<C, R>
where
    C: CurveAffine,
    C::Scalar: PrimeField,
    <C::Scalar as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]> + From<[u8; 0x20]>,
    <C::Base as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]>,
{
    fn read_point(&mut self) -> io::Result<C> {
        let mut reprs = [<C::Base as PrimeField>::Repr::default(); 2];
        for repr in &mut reprs {
            self.stream.read_exact(repr.as_mut())?;
            // The proof stream stores each coord big-endian (matches the
            // EIP-2537 wire format). `Fq::to_repr()` is always little-
            // endian, so reverse the bytes before handing them to
            // `from_repr`.
            repr.as_mut().reverse();
        }
        let [x, y] = reprs.map(|repr| Option::from(C::Base::from_repr(repr)));
        let ec_point = x
            .zip(y)
            .and_then(|(x, y)| Option::from(C::from_xy(x, y)))
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "Invalid elliptic curve point".to_string(),
                )
            })?;
        self.common_point(ec_point)?;
        Ok(ec_point)
    }

    fn read_scalar(&mut self) -> io::Result<C::Scalar> {
        let mut data = [0u8; 0x20];
        self.stream.read_exact(&mut data)?;
        data.reverse();
        let repr = <C::Scalar as PrimeField>::Repr::from(data);
        let scalar = Option::from(C::Scalar::from_repr_vartime(repr))
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "Invalid scalar".to_string()))?;
        Transcript::<C, ChallengeEvm<C>>::common_scalar(self, scalar)?;
        Ok(scalar)
    }
}

impl<C, R: Read> TranscriptReadBuffer<R, C, ChallengeEvm<C>> for Keccak256Transcript<C, R>
where
    C: CurveAffine,
    C::Scalar: PrimeField,
    <C::Scalar as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]> + From<[u8; 0x20]>,
    <C::Base as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]>,
{
    fn init(reader: R) -> Self {
        Keccak256Transcript::new(reader)
    }
}

impl<C, W: Write> TranscriptWrite<C, ChallengeEvm<C>> for Keccak256Transcript<C, W>
where
    C: CurveAffine,
    C::Scalar: PrimeField,
    <C::Scalar as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]> + From<[u8; 0x20]>,
    <C::Base as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]>,
{
    fn write_point(&mut self, ec_point: C) -> io::Result<()> {
        self.common_point(ec_point)?;
        let coords = ec_point.coordinates().unwrap();
        // Write each coord as big-endian bytes (matches the EIP-2537 wire
        // format). `Fq::to_repr()` is little-endian regardless of the
        // field's `endian =` setting, so we reverse here before writing.
        for coord in [coords.x(), coords.y()] {
            let mut repr = coord.to_repr();
            repr.as_mut().reverse();
            self.stream.write_all(repr.as_ref())?;
        }
        Ok(())
    }

    fn write_scalar(&mut self, scalar: C::Scalar) -> io::Result<()> {
        Transcript::<C, ChallengeEvm<C>>::common_scalar(self, scalar)?;
        let mut data = scalar.to_repr();
        data.as_mut().reverse();
        self.stream.write_all(data.as_ref())
    }
}

impl<C, W: Write> TranscriptWriterBuffer<W, C, ChallengeEvm<C>> for Keccak256Transcript<C, W>
where
    C: CurveAffine,
    C::Scalar: PrimeField,
    <C::Scalar as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]> + From<[u8; 0x20]>,
    <C::Base as PrimeField>::Repr: AsRef<[u8]> + AsMut<[u8]>,
{
    fn init(writer: W) -> Self {
        Keccak256Transcript::new(writer)
    }

    fn finalize(self) -> W {
        self.stream
    }
}

fn u256_to_fe<F>(value: U256) -> F
where
    F: PrimeField,
    F::Repr: AsRef<[u8]> + From<[u8; 0x20]>,
{
    let value = value % modulus::<F>();
    let repr = F::Repr::from(value.to_le_bytes::<0x20>());
    F::from_repr(repr).unwrap()
}

fn modulus<F>() -> U256
where
    F: PrimeField,
    F::Repr: AsRef<[u8]>,
{
    let neg_one_repr = (-F::ONE).to_repr();
    let bytes = neg_one_repr.as_ref();
    debug_assert_eq!(bytes.len(), 32);
    let mut le = [0u8; 32];
    le.copy_from_slice(bytes);
    U256::from_le_bytes(le) + U256::from(1)
}
