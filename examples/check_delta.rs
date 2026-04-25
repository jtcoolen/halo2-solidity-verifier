use halo2_proofs::halo2curves::{bls12381::Fr, ff::PrimeField};
use ruint::aliases::U256;

fn main() {
    let delta = Fr::DELTA;
    let mut bytes = delta.to_repr();
    let bytes_le: &[u8] = bytes.as_ref();
    let mut le_arr = [0u8; 32];
    le_arr.copy_from_slice(bytes_le);
    let val = U256::from_le_bytes(le_arr);
    println!("BLS12-381 Fr::DELTA hex (BE): 0x{:064x}", val);
    println!("BLS12-381 Fr::DELTA decimal: {}", val);

    let stale = "4131629893567559867359510883348571134090853742863529169391034518566172092834";
    println!("template hardcoded:          {}", stale);
    let _ = bytes.as_mut();
}
