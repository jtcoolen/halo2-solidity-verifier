//! Shared codegen layout facts.
//!
//! This module is the single home for numeric facts that describe the
//! generated verifier's ABI, EVM word encodings, VK header, historical
//! theta-relative memory slots, and trace namespaces. Most of these values are
//! intentionally stable compatibility anchors; call sites should use the named
//! facts here instead of repeating raw literals.

/// EVM word size. BLS12-381 Fr values are rendered as one canonical
/// big-endian EVM word in calldata/memory.
pub(crate) const WORD_BYTES: usize = 0x20;
/// Solidity's scratch space reserved for hashing and short-lived compiler use.
pub(crate) const SOLIDITY_SCRATCH_SPACE_BYTES: usize = 0x40;
/// Solidity free-memory pointer slot.
pub(crate) const SOLIDITY_FREE_MEMORY_POINTER_SLOT: usize = 0x40;
/// Solidity zero slot used as the initial value for dynamic memory arrays.
pub(crate) const SOLIDITY_ZERO_SLOT: usize = 0x60;
/// First byte not reserved by Solidity's memory conventions.
pub(crate) const SOLIDITY_ALLOCATABLE_MEMORY_START: usize = 0x80;
/// The full reserved prefix: scratch, free-memory pointer, and zero slot.
pub(crate) const SOLIDITY_RESERVED_MEMORY_BYTES: usize = SOLIDITY_ALLOCATABLE_MEMORY_START;
/// Generated verifier transcript and low-memory precompile scratch base.
pub(crate) const LOW_MEMORY_SCRATCH_START: usize = SOLIDITY_ALLOCATABLE_MEMORY_START;
pub(crate) const TRANSCRIPT_BUFFER_START: usize = LOW_MEMORY_SCRATCH_START;
pub(crate) const PCS_PAIRING_SCRATCH_START: usize = LOW_MEMORY_SCRATCH_START;
pub(crate) const VERIFIER_RETURN_BUFFER_START: usize = LOW_MEMORY_SCRATCH_START;
pub(crate) const QUOTIENT_RETURN_BUFFER_START: usize = LOW_MEMORY_SCRATCH_START;
pub(crate) const VK_CONSTRUCTOR_PAYLOAD_START: usize = LOW_MEMORY_SCRATCH_START;
/// Number of EVM words in one Fr scalar.
pub(crate) const FR_WORDS: usize = 1;
/// EIP-2537 padded G1 encoding: x_hi, x_lo, y_hi, y_lo.
pub(crate) const G1_WORDS: usize = 4;
/// EIP-2537 padded G2 encoding: four Fp2 coordinates, two words each.
pub(crate) const G2_WORDS: usize = 8;
pub(crate) const FR_BYTES: usize = FR_WORDS * WORD_BYTES;
pub(crate) const G1_BYTES: usize = G1_WORDS * WORD_BYTES;
pub(crate) const G2_BYTES: usize = G2_WORDS * WORD_BYTES;
/// Native midnight-proofs compressed G1 encoding before off-chain EIP-2537 repack.
pub(crate) const G1_COMPRESSED_BYTES: usize = 48;
/// EIP-2537 G1MSM input tuple: one padded G1 plus one scalar.
pub(crate) const G1_MSM_PAIR_BYTES: usize = G1_BYTES + FR_BYTES;
/// EIP-2537 G1ADD input tuple: two padded G1 points.
pub(crate) const G1ADD_INPUT_BYTES: usize = 2 * G1_BYTES;
/// EVM modexp frame for 32-byte base, exponent, and modulus.
///
/// Layout: three 32-byte length words followed by base, exponent, modulus.
pub(crate) const MODEXP_FRAME_BYTES: usize = 0xc0;
/// Historical low-memory reservation used by scalar inversion helpers near
/// `VK_MPTR`. It is larger than the frame because older code treated the
/// surrounding 0x100-byte window as scratch; keep the same distance from
/// `VK_MPTR` when checking overlaps.
pub(crate) const MODEXP_SCRATCH_BYTES: usize = 0x100;
/// EIP-2537 pairing precompile input for one `(G1, G2)` pair.
pub(crate) const PAIRING_PAIR_BYTES: usize = G1_BYTES + G2_BYTES;
/// Two-pair KZG pairing input: `(rhs, G2)` and `(lhs, -sG2)`.
pub(crate) const PAIRING_TWO_PAIR_BYTES: usize = 2 * PAIRING_PAIR_BYTES;
/// Historical floor for the accumulator MSM input buffer.
pub(crate) const ACC_MSM_MIN_SCRATCH_BYTES: usize = 0x7000;
/// Static low-memory working set required by the PCS pairing helpers.
pub(crate) const PCS_STATIC_WORKING_WORDS: usize = 32;
/// Static two-pair KZG pairing scratch plus one return word.
pub(crate) const PAIRING_STATIC_WORKING_WORDS: usize = PAIRING_TWO_PAIR_BYTES / WORD_BYTES + 1;
/// Low-memory frame used by the final two-pair KZG pairing helper.
pub(crate) const FINAL_PAIRING_SCRATCH_START: usize = PAIRING_TWO_PAIR_BYTES;
/// Conservative low-memory decompression/modexp scratch words.
pub(crate) const MODEXP_DECOMPRESSION_WORKING_WORDS: usize = 16;

pub(crate) mod abi {
    /// Solidity selector length before ABI-encoded arguments.
    pub(crate) const SELECTOR_BYTES: usize = 0x04;
    /// `verifyProof(bytes,uint256[])` ABI head size after the selector.
    pub(crate) const VERIFY_PROOF_HEAD_BYTES: usize = 0x40;
    /// Calldata byte offset where the dynamic `proof` byte payload starts:
    /// selector (0x04) + two ABI head words (0x40) + proof length word (0x20).
    pub(crate) const VERIFY_PROOF_PROOF_CPTR: usize =
        SELECTOR_BYTES + VERIFY_PROOF_HEAD_BYTES + super::WORD_BYTES;
    /// Expected first ABI head word: offset to `proof`.
    pub(crate) const VERIFY_PROOF_PROOF_HEAD_OFFSET: usize = VERIFY_PROOF_HEAD_BYTES;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum VkHeaderSlot {
    VkDigest = 0,
    NumInstances = 1,
    K = 2,
    NInv = 3,
    Omega = 4,
    OmegaInv = 5,
    OmegaInvToL = 6,
    HasAccumulator = 7,
    AccOffset = 8,
    NumAccLimbs = 9,
    NumAccLimbBits = 10,
    G1Base = 11,
    G2Base = 15,
    NegSG2Base = 23,
}

impl VkHeaderSlot {
    pub(crate) const fn word(self) -> usize {
        self as usize
    }
}

pub(crate) const VK_HEADER_WORDS: usize = 31;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum ThetaSlot {
    Theta = 0,
    Beta = 1,
    Gamma = 2,
    TrashChallenge = 3,
    Y = 4,
    X = 5,
    X1 = 6,
    X2 = 7,
    X3 = 8,
    X4 = 9,
    FCom = 10,
    Pi = 14,
    AccLhs = 18,
    AccRhs = 22,
    XN = 26,
    XNMinus1Inv = 27,
    LLast = 28,
    LBlind = 29,
    L0 = 30,
    InstanceEval = 31,
    QuotientEval = 32,
    Quotient = 33,
    FEval = 38,
    V = 39,
    FinalCom = 40,
    PairingLhs = 44,
    PairingRhs = 48,
}

impl ThetaSlot {
    pub(crate) const fn word(self) -> usize {
        self as usize
    }
}

pub(crate) mod theta_window {
    pub(crate) const ROT_POINTS_WORD: usize = 52;
    pub(crate) const X1_POWERS_WORD: usize = 80;
    pub(crate) const Q_COM_WORD: usize = 145;
    pub(crate) const Q_EVAL_SET_WORD: usize = 145;
    pub(crate) const Q_EVAL_CPTR_WORD: usize = 201;
    pub(crate) const G1_IDENTITY_WORD: usize = 209;
    pub(crate) const REVERSED_EVALS_WORD: usize = 220;
}

pub(crate) mod trace {
    pub(crate) const PCS_QUERY_BASE: u64 = 2_000;
    pub(crate) const PROOF_COMMIT_BASE: usize = 10_000;
    pub(crate) const PROOF_EVAL_BASE: usize = 20_000;
    pub(crate) const QUOTIENT_IDENTITY_BASE: u64 = 30_000;
    pub(crate) const PCS_SERIALIZED_POINT_SET_BASE: u64 = 41_000;
    pub(crate) const SELECTOR_FOLD_BASE: usize = 60_000;
}

#[cfg(test)]
mod tests {
    use super::{abi, theta_window, trace, ThetaSlot, VkHeaderSlot};

    #[test]
    fn abi_offsets_match_verify_proof_calldata_layout() {
        assert_eq!(abi::SELECTOR_BYTES, 0x04);
        assert_eq!(abi::VERIFY_PROOF_HEAD_BYTES, 0x40);
        assert_eq!(abi::VERIFY_PROOF_PROOF_CPTR, 0x64);
        assert_eq!(abi::VERIFY_PROOF_PROOF_HEAD_OFFSET, 0x40);
    }

    #[test]
    fn solidity_reserved_memory_constants_match_compiler_conventions() {
        assert_eq!(super::SOLIDITY_SCRATCH_SPACE_BYTES, 0x40);
        assert_eq!(super::SOLIDITY_FREE_MEMORY_POINTER_SLOT, 0x40);
        assert_eq!(super::SOLIDITY_ZERO_SLOT, 0x60);
        assert_eq!(super::SOLIDITY_RESERVED_MEMORY_BYTES, 0x80);
        assert_eq!(super::TRANSCRIPT_BUFFER_START, 0x80);
        assert_eq!(super::VK_CONSTRUCTOR_PAYLOAD_START, 0x80);
    }

    #[test]
    fn vk_header_slots_preserve_generated_payload_layout() {
        assert_eq!(VkHeaderSlot::VkDigest.word(), 0);
        assert_eq!(VkHeaderSlot::G1Base.word(), 11);
        assert_eq!(VkHeaderSlot::G2Base.word(), 15);
        assert_eq!(VkHeaderSlot::NegSG2Base.word(), 23);
        assert_eq!(super::VK_HEADER_WORDS, 31);
    }

    #[test]
    fn theta_slots_and_windows_preserve_historical_offsets() {
        assert_eq!(ThetaSlot::Theta.word(), 0);
        assert_eq!(ThetaSlot::Quotient.word(), 33);
        assert_eq!(ThetaSlot::PairingRhs.word(), 48);
        assert_eq!(theta_window::ROT_POINTS_WORD, 52);
        assert_eq!(theta_window::X1_POWERS_WORD, 80);
        assert_eq!(theta_window::Q_EVAL_SET_WORD, 145);
        assert_eq!(theta_window::Q_EVAL_CPTR_WORD, 201);
        assert_eq!(theta_window::G1_IDENTITY_WORD, 209);
        assert_eq!(theta_window::REVERSED_EVALS_WORD, 220);
    }

    #[test]
    fn trace_namespaces_preserve_existing_ids() {
        assert_eq!(trace::PCS_QUERY_BASE, 2_000);
        assert_eq!(trace::PROOF_COMMIT_BASE, 10_000);
        assert_eq!(trace::PROOF_EVAL_BASE, 20_000);
        assert_eq!(trace::QUOTIENT_IDENTITY_BASE, 30_000);
        assert_eq!(trace::PCS_SERIALIZED_POINT_SET_BASE, 41_000);
        assert_eq!(trace::SELECTOR_FOLD_BASE, 60_000);
    }
}
