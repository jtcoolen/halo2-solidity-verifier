//! Quick sanity check: decompress various proof G1s using midnight-curves'
//! blst-backed G1 decoder and check what we get vs. what the Yul does.

#![cfg(feature = "evm")]

use group::{prime::PrimeCurveAffine, GroupEncoding};
use midnight_curves::G1Affine;

#[test]
#[ignore = "diagnostic-only compressed point probe; captured bytes are not part of CI acceptance"]
fn fcom_decompress() {
    let bytes_hex = "e910f0d3fc7d02235d9c7953d44923684ef8a25ba83e8c80e345f7c2b4827257cabfb6830aa5aefacb690f81404d0b2d";
    let bytes: [u8; 48] = hex::decode(bytes_hex).unwrap().try_into().unwrap();
    let mut compressed = <G1Affine as GroupEncoding>::Repr::default();
    compressed.as_mut().copy_from_slice(&bytes);
    let opt = G1Affine::from_bytes(&compressed);
    let success = bool::from(opt.is_some());
    eprintln!("from_bytes ok: {}", success);
    assert!(success, "f_com should decode");
    let p = opt.unwrap();
    eprintln!("is_identity: {}", bool::from(p.is_identity()));
    let bytes2 = p.to_bytes();
    eprintln!("re-serialized hex: {}", hex::encode(bytes2.as_ref()));
    eprintln!("matches: {}", bytes2.as_ref() == bytes);
}

/// Decompress one of the quotient limb compressed bytes captured by the
/// Yul probe and dump the resulting (x, y) for cross-check.
#[test]
#[ignore = "diagnostic-only compressed point probe; captured bytes are not part of CI acceptance"]
fn quotient_limb_decompress() {
    // Captured from the Yul `return(0x500, 0xc0)` probe in the previous run.
    let compressed_hex = "8c0b3ee2ff547acc7650d83ad9bbe7ccc82f4563026996f058831e9555a9b99ebbfdd23a31fd4d6f71983ba017bb87fc";
    let bytes: [u8; 48] = hex::decode(compressed_hex).unwrap().try_into().unwrap();
    let mut repr = <G1Affine as GroupEncoding>::Repr::default();
    repr.as_mut().copy_from_slice(&bytes);
    let opt = G1Affine::from_bytes(&repr);
    let success = bool::from(opt.is_some());
    eprintln!("decompress ok: {}", success);
    assert!(success, "quotient limb should decompress");
    let p = opt.unwrap();
    eprintln!("identity: {}", bool::from(p.is_identity()));
    // Print x, y as 48-byte big-endian hex.
    let x_bytes = p.x().to_bytes_be();
    let y_bytes = p.y().to_bytes_be();
    eprintln!("blst   x = {}", hex::encode(x_bytes));
    eprintln!("blst   y = {}", hex::encode(y_bytes));
    // Yul-produced (from the probe output we just got).
    let yul_x = "0c0b3ee2ff547acc7650d83ad9bbe7ccc82f4563026996f058831e9555a9b99ebbfdd23a31fd4d6f71983ba017bb87fc";
    let yul_y = "068a5df3c9c3cbc6ecefea3b311bd79ead7eff0cd580007152221b72407b8b2218934f928ef73ff3c22f6f78b2b444c1";
    eprintln!("yul    x = {yul_x}");
    eprintln!("yul    y = {yul_y}");
    eprintln!("x match: {}", hex::encode(x_bytes) == yul_x);
    eprintln!("y match: {}", hex::encode(y_bytes) == yul_y);
}
