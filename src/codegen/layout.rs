//! Shared codegen layout facts.
//!
//! This module is the single home for numeric facts that describe the
//! generated verifier's ABI, EVM word encodings, VK header, historical
//! theta-relative memory slots, and trace namespaces. Most of these values are
//! intentionally stable compatibility anchors; call sites should use the named
//! facts here instead of repeating raw literals.

use ruint::aliases::U256;

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
/// Big-endian byte length of an unpadded BLS12-381 base-field coordinate.
pub(crate) const BLS_FP_BYTES: usize = 48;
/// EIP-2537 pads each 48-byte Fp coordinate with 16 leading zero bytes.
pub(crate) const EIP2537_FP_PAD_BYTES: usize = 16;
/// EIP-2537 G1MSM input tuple: one padded G1 plus one scalar.
pub(crate) const G1_MSM_PAIR_BYTES: usize = G1_BYTES + FR_BYTES;
/// EIP-2537 G1ADD input tuple: two padded G1 points.
pub(crate) const G1ADD_INPUT_BYTES: usize = 2 * G1_BYTES;
/// EVM modexp frame for 32-byte base, exponent, and modulus.
///
/// Layout: three 32-byte length words followed by base, exponent, modulus.
pub(crate) const MODEXP_FRAME_WORDS: usize = 6;
pub(crate) const MODEXP_FRAME_BYTES: usize = MODEXP_FRAME_WORDS * WORD_BYTES;
/// Historical low-memory reservation used by scalar inversion helpers near
/// `VK_MPTR`. It is larger than the frame because older code treated the
/// surrounding 0x100-byte window as scratch; keep the same distance from
/// `VK_MPTR` when checking overlaps.
pub(crate) const MODEXP_SCRATCH_WORDS: usize = 8;
pub(crate) const MODEXP_SCRATCH_BYTES: usize = MODEXP_SCRATCH_WORDS * WORD_BYTES;
/// EIP-2537 pairing precompile input for one `(G1, G2)` pair.
pub(crate) const PAIRING_PAIR_BYTES: usize = G1_BYTES + G2_BYTES;
/// Two-pair KZG pairing input: `(rhs, G2)` and `(lhs, -sG2)`.
pub(crate) const PAIRING_TWO_PAIR_BYTES: usize = 2 * PAIRING_PAIR_BYTES;
/// Historical floor for the accumulator MSM input buffer.
///
/// This is deliberately not derived from the current proof shape: smaller
/// circuits keep the same generated addresses as the compatibility template.
pub(crate) const ACC_MSM_MIN_SCRATCH_BYTES: usize = 0x7000;
/// Static low-memory working set required by the PCS pairing helpers.
///
/// The final pairing frame needs 25 words (two `(G1, G2)` pairs plus one return
/// word); production PCS code rounds this up to leave room for intermediate
/// in-Yul accumulators.
pub(crate) const PCS_STATIC_WORKING_WORDS: usize = 32;
/// Static two-pair KZG pairing scratch plus one return word.
pub(crate) const PAIRING_STATIC_WORKING_WORDS: usize = PAIRING_TWO_PAIR_BYTES / WORD_BYTES + 1;
/// Low-memory frame used by the final two-pair KZG pairing helper.
pub(crate) const FINAL_PAIRING_SCRATCH_START: usize = PAIRING_TWO_PAIR_BYTES;
/// Conservative low-memory decompression/modexp scratch words.
pub(crate) const MODEXP_DECOMPRESSION_WORKING_WORDS: usize = 16;

pub(crate) mod precompile {
    //! EVM precompile addresses, frame lengths, and gas constants used by the
    //! generated verifier. These values come from EIP-198 and EIP-2537; keep
    //! template call sites wired through these names so future fork changes are
    //! not hidden in hand-written Yul literals.

    /// EIP-198 modexp precompile.
    pub(crate) const MODEXP_ADDRESS: usize = 0x05;
    /// Prague/EIP-2537 BLS12-381 G1ADD precompile.
    pub(crate) const G1ADD_ADDRESS: usize = 0x0b;
    /// Prague/EIP-2537 BLS12-381 G1MSM precompile.
    pub(crate) const G1MSM_ADDRESS: usize = 0x0c;
    /// Prague/EIP-2537 BLS12-381 pairing precompile.
    pub(crate) const PAIRING_ADDRESS: usize = 0x0f;

    /// Deployment smoke-test gas caps. They are intentionally above the single
    /// operation costs, but still bounded enough to catch missing precompiles.
    pub(crate) const G1ADD_GAS_CAP: usize = 50_000;
    pub(crate) const G1MSM_SMOKE_GAS_CAP: usize = 60_000;
    pub(crate) const PAIRING_SMOKE_GAS_CAP: usize = 120_000;
    /// EIP-2537 G1MSM gas formula: `base + k * discount[k] * mul_cost / 1000`.
    pub(crate) const G1MSM_BASE_GAS: usize = 50_000;
    pub(crate) const G1MSM_SCALAR_MULTIPLICATION_COST: usize = 12_000;
    pub(crate) const G1MSM_DISCOUNT_DENOMINATOR: usize = 1_000;
    /// EIP-2537 pairing gas formula: base + pair_count * pair_cost.
    pub(crate) const PAIRING_BASE_GAS: usize = 50_000;
    pub(crate) const PAIRING_PAIR_GAS: usize = 60_000;

    /// EIP-2537 G1MSM discount table for k = 0..128.
    ///
    /// k=0 is not a real precompile input shape for verifier calls, but keeping
    /// it in the table preserves the previous Yul helper's behavior.
    pub(crate) const G1MSM_DISCOUNT_TABLE: [usize; 129] = [
        0, 1000, 949, 848, 797, 764, 750, 738, 728, 719, 712, 705, 698, 692, 687, 682, 677, 673,
        669, 665, 661, 658, 654, 651, 648, 645, 642, 640, 637, 635, 632, 630, 627, 625, 623, 621,
        619, 617, 615, 613, 611, 609, 608, 606, 604, 603, 601, 599, 598, 596, 595, 593, 592, 591,
        589, 588, 586, 585, 584, 582, 581, 580, 579, 577, 576, 575, 574, 573, 572, 570, 569, 568,
        567, 566, 565, 564, 563, 562, 561, 560, 559, 558, 557, 556, 555, 554, 553, 552, 551, 550,
        549, 548, 547, 547, 546, 545, 544, 543, 542, 541, 540, 540, 539, 538, 537, 536, 536, 535,
        534, 533, 532, 532, 531, 530, 529, 528, 528, 527, 526, 525, 525, 524, 523, 522, 522, 521,
        520, 520, 519,
    ];

    /// Return the bounded gas cap for a G1MSM input of `input_len` bytes.
    ///
    /// Pinned verifier codegen knows each static MSM input length, so rendering
    /// this value as a literal avoids carrying the whole discount-table switch
    /// in deployed Yul.
    pub(crate) fn g1msm_gas_cap(input_len: usize) -> usize {
        let k = input_len / super::G1_MSM_PAIR_BYTES;
        let discount = G1MSM_DISCOUNT_TABLE.get(k).copied().unwrap_or(519);
        G1MSM_BASE_GAS
            + k * discount * G1MSM_SCALAR_MULTIPLICATION_COST / G1MSM_DISCOUNT_DENOMINATOR
    }

    /// Return the bounded gas cap for a pairing input of `input_len` bytes.
    pub(crate) fn pairing_gas_cap(input_len: usize) -> usize {
        PAIRING_BASE_GAS + (input_len / super::PAIRING_PAIR_BYTES) * PAIRING_PAIR_GAS
    }
}

pub(crate) mod modexp_frame {
    //! 32-byte base/exponent/modulus EIP-198 frame offsets.

    use super::WORD_BYTES;

    pub(crate) const BASE_LEN_OFFSET: usize = 0 * WORD_BYTES;
    pub(crate) const EXP_LEN_OFFSET: usize = 1 * WORD_BYTES;
    pub(crate) const MOD_LEN_OFFSET: usize = 2 * WORD_BYTES;
    pub(crate) const BASE_OFFSET: usize = 3 * WORD_BYTES;
    pub(crate) const EXP_OFFSET: usize = 4 * WORD_BYTES;
    pub(crate) const MOD_OFFSET: usize = 5 * WORD_BYTES;
}

pub(crate) mod accumulator {
    //! Public-input encoding used by `AssignedAccumulator<S>::as_public_input`
    //! for the current BLS12-381 self-emulation circuits.

    use super::{G1_BYTES, WORD_BYTES};

    /// `AssignedField::as_public_input` uses seven radix-2^56 limbs for one
    /// BLS12-381 base-field coordinate.
    pub(crate) const LIMB_BITS: usize = 56;
    pub(crate) const LIMBS: usize = 7;
    /// Four 56-bit limbs fit in one scalar word with unused high bits.
    pub(crate) const LIMBS_PER_WORD: usize = 4;
    pub(crate) const POINT_COORDS: usize = 2;
    pub(crate) const CARRIED_SCALARS: usize = 2;
    /// Low-memory hash frame for batching the accumulator pairing with KZG:
    /// domain tag word, KZG rhs/lhs G1s, then accumulator rhs/lhs G1s.
    pub(crate) const PAIRING_BATCH_PTR: usize = 0x100;
    /// ASCII `"pairing-batch-acc-kzg"` right-padded to one EVM word.
    pub(crate) const PAIRING_BATCH_DOMAIN_TAG_HEX: &str =
        "0x70616972696e672d62617463682d6163632d6b7a670000000000000000";
    pub(crate) const PAIRING_BATCH_RHS_OFFSET: usize = WORD_BYTES;
    pub(crate) const PAIRING_BATCH_LHS_OFFSET: usize = WORD_BYTES + G1_BYTES;
    pub(crate) const PAIRING_BATCH_ACC_RHS_OFFSET: usize = WORD_BYTES + 2 * G1_BYTES;
    pub(crate) const PAIRING_BATCH_ACC_LHS_OFFSET: usize = WORD_BYTES + 3 * G1_BYTES;
    pub(crate) const PAIRING_BATCH_HASH_BYTES: usize = WORD_BYTES + 4 * G1_BYTES;
}

pub(crate) mod quotient_limb {
    //! Foreign-field limb-specialized quotient VM shapes.

    /// Matches the accumulator/public-input BLS12-381 base-field limb packing.
    pub(crate) const LIMBS: usize = 7;
    /// Linear reduction coefficients for limbs 1..6 after keeping limb 0 raw.
    pub(crate) const LIN_COEFFS: usize = LIMBS - 1;
    /// Full 7x7 schoolbook multiplication grid.
    pub(crate) const PAIRWISE_TERMS: usize = LIMBS * LIMBS;
    /// Output diagonals for a 7-limb by 7-limb product.
    pub(crate) const PAIRWISE_COEFFS: usize = 2 * LIMBS - 1;
}

pub(crate) mod transcript {
    //! Transcript buffer bound heuristics. These are not protocol constants;
    //! they are gas/codegen guardrails used by `transcript_buffer_words_bound`.

    use super::{G1_BYTES, WORD_BYTES};

    pub(crate) const WORD_ABSORB_BYTES: usize = WORD_BYTES;
    pub(crate) const G1_ABSORB_BYTES: usize = G1_BYTES;
    pub(crate) const POST_SQUEEZE_CUSHION_WORDS: usize = 32;
}

pub(crate) mod abi {
    /// Solidity selector length before ABI-encoded arguments.
    pub(crate) const SELECTOR_BYTES: usize = 0x04;
    /// `verifyProof(bytes,uint256[])` has two ABI head words after the selector.
    pub(crate) const VERIFY_PROOF_HEAD_WORDS: usize = 2;
    /// `verifyProof(bytes,uint256[])` ABI head size after the selector.
    pub(crate) const VERIFY_PROOF_HEAD_BYTES: usize = VERIFY_PROOF_HEAD_WORDS * super::WORD_BYTES;
    /// Calldata byte offset where the dynamic `proof` byte payload starts:
    /// selector (0x04) + two ABI head words (0x40) + proof length word (0x20).
    pub(crate) const VERIFY_PROOF_PROOF_CPTR: usize =
        SELECTOR_BYTES + VERIFY_PROOF_HEAD_BYTES + super::WORD_BYTES;
    /// Expected first ABI head word: offset to `proof`.
    pub(crate) const VERIFY_PROOF_PROOF_HEAD_OFFSET: usize = VERIFY_PROOF_HEAD_BYTES;
}

/// Number of scalar words before embedded SRS base points in the VK header.
const VK_HEADER_SCALAR_WORDS: usize = 11;
/// Header word where the padded G1 generator starts.
const VK_HEADER_G1_BASE_WORD: usize = VK_HEADER_SCALAR_WORDS;
/// Header word where the padded G2 generator starts.
const VK_HEADER_G2_BASE_WORD: usize = VK_HEADER_G1_BASE_WORD + G1_WORDS;
/// Header word where the padded `-sG2` point starts.
const VK_HEADER_NEG_S_G2_BASE_WORD: usize = VK_HEADER_G2_BASE_WORD + G2_WORDS;

/// Stable word slots in the generated verifying-key header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum VkHeaderSlot {
    /// Fiat-Shamir VK digest absorbed before proof data.
    VkDigest = 0,
    /// Expected public instance count.
    NumInstances = 1,
    /// Evaluation-domain exponent.
    K = 2,
    /// Multiplicative inverse of domain size.
    NInv = 3,
    /// Domain generator.
    Omega = 4,
    /// Inverse domain generator.
    OmegaInv = 5,
    /// `omega_inv^last_rotation_abs` for negative-row Lagrange terms.
    OmegaInvToL = 6,
    /// Boolean flag for optional public accumulator batching.
    HasAccumulator = 7,
    /// Public-input offset of accumulator encoding.
    AccOffset = 8,
    /// Limbs per BLS base-field coordinate in accumulator encoding.
    NumAccLimbs = 9,
    /// Bits per accumulator limb.
    NumAccLimbBits = 10,
    /// Padded G1 generator.
    G1Base = VK_HEADER_G1_BASE_WORD,
    /// Padded G2 generator.
    G2Base = VK_HEADER_G2_BASE_WORD,
    /// Padded negated SRS `sG2` point.
    NegSG2Base = VK_HEADER_NEG_S_G2_BASE_WORD,
}

impl VkHeaderSlot {
    /// Return the word offset of this header slot.
    pub(crate) const fn word(self) -> usize {
        self as usize
    }
}

/// Total number of EVM words in the VK header.
pub(crate) const VK_HEADER_WORDS: usize = VK_HEADER_NEG_S_G2_BASE_WORD + G2_WORDS;

/// Schema descriptor for one VK header field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VkHeaderFieldSpec {
    /// First slot occupied by the field.
    pub(crate) slot: VkHeaderSlot,
    /// Stable source/debug name.
    pub(crate) name: &'static str,
    /// Field width in EVM words.
    pub(crate) width_words: usize,
}

/// Ordered VK header schema.
pub(crate) const VK_HEADER_FIELDS: [VkHeaderFieldSpec; 14] = [
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::VkDigest,
        name: "vk_digest",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::NumInstances,
        name: "num_instances",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::K,
        name: "k",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::NInv,
        name: "n_inv",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::Omega,
        name: "omega",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::OmegaInv,
        name: "omega_inv",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::OmegaInvToL,
        name: "omega_inv_to_l",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::HasAccumulator,
        name: "has_accumulator",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::AccOffset,
        name: "acc_offset",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::NumAccLimbs,
        name: "num_acc_limbs",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::NumAccLimbBits,
        name: "num_acc_limb_bits",
        width_words: 1,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::G1Base,
        name: "G1_BASE",
        width_words: G1_WORDS,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::G2Base,
        name: "G2_BASE",
        width_words: G2_WORDS,
    },
    VkHeaderFieldSpec {
        slot: VkHeaderSlot::NegSG2Base,
        name: "NEG_S_G2_BASE",
        width_words: G2_WORDS,
    },
];

/// Accessor namespace for the stable VK header schema.
pub(crate) struct VkHeaderLayout;

impl VkHeaderLayout {
    /// Return the total header width in EVM words.
    pub(crate) const fn header_words() -> usize {
        VK_HEADER_WORDS
    }

    /// Return every header field descriptor in render order.
    pub(crate) fn fields() -> &'static [VkHeaderFieldSpec] {
        &VK_HEADER_FIELDS
    }

    /// Return the descriptor for a single slot.
    pub(crate) fn field(slot: VkHeaderSlot) -> VkHeaderFieldSpec {
        let fields = Self::fields();
        let mut idx = 0;
        while idx < fields.len() {
            if fields[idx].slot as usize == slot as usize {
                return fields[idx];
            }
            idx += 1;
        }
        panic!("unknown VK header slot")
    }

    /// Create an empty checked header builder.
    pub(crate) fn builder() -> VkHeaderBuilder {
        VkHeaderBuilder::new()
    }
}

/// Checked writer for the VK header constant vector.
#[derive(Clone, Debug)]
pub(crate) struct VkHeaderBuilder {
    words: Vec<Option<(&'static str, U256)>>,
}

impl VkHeaderBuilder {
    /// Create a builder with every header word initially unset.
    pub(crate) fn new() -> Self {
        Self {
            words: vec![None; VkHeaderLayout::header_words()],
        }
    }

    /// Insert a field at its schema-defined slot, checking width and overlap.
    pub(crate) fn insert(
        &mut self,
        slot: VkHeaderSlot,
        expected_width: usize,
        values: &[(&'static str, U256)],
    ) -> Result<(), String> {
        let spec = VkHeaderLayout::field(slot);
        if spec.width_words != expected_width {
            return Err(format!(
                "VK header field {} width mismatch: descriptor={} caller={expected_width}",
                spec.name, spec.width_words
            ));
        }
        if values.len() != spec.width_words {
            return Err(format!(
                "VK header field {} expected {} word(s), got {}",
                spec.name,
                spec.width_words,
                values.len()
            ));
        }
        let start = spec.slot.word();
        let end = start + spec.width_words;
        if end > self.words.len() {
            return Err(format!(
                "VK header field {} overflows header: range {start}..{end}, header={}",
                spec.name,
                self.words.len()
            ));
        }
        for (offset, value) in values.iter().copied().enumerate() {
            let word = start + offset;
            if self.words[word].is_some() {
                return Err(format!(
                    "VK header field {} overlaps already-written word {word}",
                    spec.name
                ));
            }
            self.words[word] = Some(value);
        }
        Ok(())
    }

    /// Insert a one-word scalar header field.
    pub(crate) fn scalar(
        &mut self,
        slot: VkHeaderSlot,
        name: &'static str,
        value: U256,
    ) -> Result<(), String> {
        self.insert(slot, 1, &[(name, value)])
    }

    /// Insert a padded G1 header field.
    pub(crate) fn g1(
        &mut self,
        slot: VkHeaderSlot,
        names: [&'static str; G1_WORDS],
        values: [U256; G1_WORDS],
    ) -> Result<(), String> {
        let words = names
            .into_iter()
            .zip(values)
            .collect::<Vec<(&'static str, U256)>>();
        self.insert(slot, G1_WORDS, &words)
    }

    /// Insert a padded G2 header field.
    pub(crate) fn g2(
        &mut self,
        slot: VkHeaderSlot,
        names: [&'static str; G2_WORDS],
        values: [U256; G2_WORDS],
    ) -> Result<(), String> {
        let words = names
            .into_iter()
            .zip(values)
            .collect::<Vec<(&'static str, U256)>>();
        self.insert(slot, G2_WORDS, &words)
    }

    /// Return the completed header or report the first missing word.
    pub(crate) fn finish(self) -> Result<Vec<(&'static str, U256)>, String> {
        self.words
            .into_iter()
            .enumerate()
            .map(|(word, value)| {
                value.ok_or_else(|| format!("VK header word {word} was not written"))
            })
            .collect()
    }
}

/// Historical word slots rooted at `THETA_MPTR`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub(crate) enum ThetaSlot {
    /// Lookup compression challenge.
    Theta = 0,
    /// Permutation/lookup beta challenge.
    Beta = 1,
    /// Permutation/lookup gamma challenge.
    Gamma = 2,
    /// Trash argument compression challenge.
    TrashChallenge = 3,
    /// Quotient identity batch challenge.
    Y = 4,
    /// Evaluation point.
    X = 5,
    /// PCS challenge x1.
    X1 = 6,
    /// PCS challenge x2.
    X2 = 7,
    /// PCS challenge x3.
    X3 = 8,
    /// PCS challenge x4.
    X4 = 9,
    /// KZG `f_com` G1 slot.
    FCom = 10,
    /// KZG proof commitment `pi` G1 slot.
    Pi = 14,
    /// Public accumulator left-hand G1 slot.
    AccLhs = 18,
    /// Public accumulator right-hand G1 slot.
    AccRhs = 22,
    /// `x^n` scalar slot.
    XN = 26,
    /// `(x^n - 1)^-1` scalar slot.
    XNMinus1Inv = 27,
    /// Last-row Lagrange scalar slot.
    LLast = 28,
    /// Blinding-row Lagrange scalar slot.
    LBlind = 29,
    /// First-row Lagrange scalar slot.
    L0 = 30,
    /// Locally interpolated public-instance evaluation.
    InstanceEval = 31,
    /// Negated quotient numerator evaluation.
    QuotientEval = 32,
    /// Quotient linearization scratch G1-sized slot.
    Quotient = 33,
    /// PCS `f_eval` scalar slot.
    FEval = 38,
    /// PCS `v` scalar slot.
    V = 39,
    /// Final linearized commitment G1 slot.
    FinalCom = 40,
    /// Final pairing LHS G1 slot.
    PairingLhs = 44,
    /// Final pairing RHS G1 slot.
    PairingRhs = 48,
}

impl ThetaSlot {
    /// Return this slot's word offset relative to `THETA_MPTR`.
    pub(crate) const fn word(self) -> usize {
        self as usize
    }
}

pub(crate) mod theta_window {
    //! Historical word offsets from `THETA_MPTR` for the fixed PCS windows.
    //!
    //! The first 52 words are covered by `ThetaSlot`: ten challenge/scalar words,
    //! four G1 slots, more scalar state, a historical padding word, and three
    //! final G1 slots. The windows below preserve the old generated layout while
    //! making their capacities explicit.

    use super::{ThetaSlot, G1_WORDS};

    pub(crate) const ROT_POINTS_CAP_WORDS: usize = 28;
    pub(crate) const X1_POWERS_CAP_WORDS: usize = 65;
    pub(crate) const Q_EVAL_SET_CAP_WORDS: usize = 56;
    pub(crate) const Q_EVAL_CPTR_PADDING_WORDS: usize = 7;
    pub(crate) const G1_IDENTITY_PADDING_WORDS: usize = 7;

    pub(crate) const ROT_POINTS_WORD: usize = ThetaSlot::PairingRhs.word() + G1_WORDS;
    pub(crate) const X1_POWERS_WORD: usize = ROT_POINTS_WORD + ROT_POINTS_CAP_WORDS;
    pub(crate) const Q_COM_WORD: usize = X1_POWERS_WORD + X1_POWERS_CAP_WORDS;
    pub(crate) const Q_EVAL_SET_WORD: usize = Q_COM_WORD;
    pub(crate) const Q_COM_CAP_WORDS: usize = Q_EVAL_SET_WORD - Q_COM_WORD;
    pub(crate) const Q_EVAL_CPTR_WORD: usize = Q_EVAL_SET_WORD + Q_EVAL_SET_CAP_WORDS;
    pub(crate) const G1_IDENTITY_WORD: usize = Q_EVAL_CPTR_WORD + 1 + Q_EVAL_CPTR_PADDING_WORDS;
    pub(crate) const REVERSED_EVALS_WORD: usize =
        G1_IDENTITY_WORD + G1_WORDS + G1_IDENTITY_PADDING_WORDS;
}

pub(crate) mod trace {
    //! LOG topic namespaces used by trace-enabled builds.
    //!
    //! The gaps are intentional: they keep broad event families visually
    //! separated in traces and preserve historical IDs consumed by tests and
    //! external comparison scripts.

    pub(crate) const PCS_QUERY_BASE: u64 = 2_000;
    pub(crate) const PROOF_COMMIT_BASE: usize = 10_000;
    pub(crate) const PROOF_EVAL_BASE: usize = 20_000;
    pub(crate) const QUOTIENT_IDENTITY_BASE: u64 = 30_000;
    pub(crate) const PCS_SERIALIZED_POINT_SET_BASE: u64 = 41_000;
    pub(crate) const SELECTOR_FOLD_BASE: usize = 60_000;
}

#[cfg(test)]
mod tests {
    use super::{
        abi, accumulator, modexp_frame, precompile, quotient_limb, theta_window, trace, transcript,
        ThetaSlot, VkHeaderLayout, VkHeaderSlot,
    };
    use ruint::aliases::U256;

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
        assert_eq!(VkHeaderLayout::header_words(), 31);
        assert_eq!(
            VkHeaderLayout::fields()
                .iter()
                .map(|field| field.width_words)
                .sum::<usize>(),
            31
        );
    }

    #[test]
    fn vk_header_builder_rejects_missing_duplicate_and_width_errors() {
        let builder = VkHeaderLayout::builder();
        assert!(builder.finish().unwrap_err().contains("word 0"));

        let mut builder = VkHeaderLayout::builder();
        builder
            .scalar(VkHeaderSlot::VkDigest, "vk_digest", U256::from(1u64))
            .unwrap();
        let err = builder
            .scalar(VkHeaderSlot::VkDigest, "vk_digest", U256::from(2u64))
            .unwrap_err();
        assert!(err.contains("overlaps"));

        let mut builder = VkHeaderLayout::builder();
        let err = builder
            .insert(VkHeaderSlot::G1Base, 8, &[("too_wide", U256::ZERO)])
            .unwrap_err();
        assert!(err.contains("width mismatch"));

        let mut builder = super::VkHeaderBuilder {
            words: vec![None; super::VK_HEADER_WORDS - 1],
        };
        let words = [("neg_s_g2", U256::ZERO); super::G2_WORDS];
        let err = builder
            .insert(VkHeaderSlot::NegSG2Base, super::G2_WORDS, &words)
            .unwrap_err();
        assert!(err.contains("overflows"));
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

    #[test]
    fn precompile_and_modexp_constants_preserve_existing_frames() {
        assert_eq!(precompile::MODEXP_ADDRESS, 0x05);
        assert_eq!(precompile::G1ADD_ADDRESS, 0x0b);
        assert_eq!(precompile::G1MSM_ADDRESS, 0x0c);
        assert_eq!(precompile::PAIRING_ADDRESS, 0x0f);
        assert_eq!(precompile::G1ADD_GAS_CAP, 50_000);
        assert_eq!(precompile::G1MSM_SMOKE_GAS_CAP, 60_000);
        assert_eq!(precompile::PAIRING_SMOKE_GAS_CAP, 120_000);
        assert_eq!(modexp_frame::BASE_LEN_OFFSET, 0x00);
        assert_eq!(modexp_frame::EXP_LEN_OFFSET, 0x20);
        assert_eq!(modexp_frame::MOD_LEN_OFFSET, 0x40);
        assert_eq!(modexp_frame::BASE_OFFSET, 0x60);
        assert_eq!(modexp_frame::EXP_OFFSET, 0x80);
        assert_eq!(modexp_frame::MOD_OFFSET, 0xa0);
    }

    #[test]
    fn accumulator_and_limb_constants_preserve_current_encoding() {
        assert_eq!(accumulator::LIMB_BITS, 56);
        assert_eq!(accumulator::LIMBS, 7);
        assert_eq!(accumulator::LIMBS_PER_WORD, 4);
        assert_eq!(accumulator::PAIRING_BATCH_PTR, 0x100);
        assert_eq!(accumulator::PAIRING_BATCH_HASH_BYTES, 0x220);
        assert_eq!(quotient_limb::LIMBS, 7);
        assert_eq!(quotient_limb::PAIRWISE_TERMS, 49);
        assert_eq!(quotient_limb::PAIRWISE_COEFFS, 13);
    }

    #[test]
    fn transcript_bound_constants_preserve_absorb_sizes() {
        assert_eq!(transcript::WORD_ABSORB_BYTES, 0x20);
        assert_eq!(transcript::G1_ABSORB_BYTES, 0x80);
        assert_eq!(transcript::POST_SQUEEZE_CUSHION_WORDS, 32);
    }
}
