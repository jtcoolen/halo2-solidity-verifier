use crate::codegen::{
    template::Halo2VerifyingKey,
    BatchOpenScheme::{self, Bdfg21, Gwc19},
};
// IMPORTANT: bn256 must come from halo2_proofs (which transitively uses
// halo2curves 0.6) so the types unify with the rest of the codebase. We pull
// the bls12_381 module separately from halo2curves 0.7+, where it's exposed
// as `bls12381` (note: no underscore in 0.7).
use halo2_proofs::halo2curves::{bn256, ff::PrimeField, CurveAffine};
use halo2curves::bls12381 as bls12_381;
use halo2_proofs::plonk::{Any, Column, ConstraintSystem};
use itertools::{chain, izip, Itertools};
use ruint::{aliases::U256, UintTryFrom};
use std::{
    borrow::Borrow,
    collections::HashMap,
    fmt::{self, Display, Formatter},
    ops::{Add, Sub},
};

#[derive(Debug)]
pub(crate) struct ConstraintSystemMeta {
    pub(crate) num_fixeds: usize,
    pub(crate) permutation_columns: Vec<Column<Any>>,
    pub(crate) permutation_chunk_len: usize,
    pub(crate) num_lookup_permuteds: usize,
    pub(crate) num_permutation_zs: usize,
    pub(crate) num_lookup_zs: usize,
    pub(crate) num_quotients: usize,
    pub(crate) advice_queries: Vec<(usize, i32)>,
    pub(crate) fixed_queries: Vec<(usize, i32)>,
    pub(crate) num_rotations: usize,
    pub(crate) num_evals: usize,
    pub(crate) num_user_advices: Vec<usize>,
    pub(crate) num_user_challenges: Vec<usize>,
    pub(crate) advice_indices: Vec<usize>,
    pub(crate) challenge_indices: Vec<usize>,
    pub(crate) rotation_last: i32,
}

impl ConstraintSystemMeta {
    pub(crate) fn new(cs: &ConstraintSystem<impl PrimeField>) -> Self {
        let num_fixeds = cs.num_fixed_columns();
        let permutation_columns = cs.permutation().get_columns();
        let permutation_chunk_len = cs.degree() - 2;
        let num_lookup_permuteds = 2 * cs.lookups().len();
        let num_permutation_zs = cs
            .permutation()
            .get_columns()
            .chunks(cs.degree() - 2)
            .count();
        let num_lookup_zs = cs.lookups().len();
        let num_quotients = cs.degree() - 1;
        let advice_queries = cs
            .advice_queries()
            .iter()
            .map(|(column, rotation)| (column.index(), rotation.0))
            .collect_vec();
        let fixed_queries = cs
            .fixed_queries()
            .iter()
            .map(|(column, rotation)| (column.index(), rotation.0))
            .collect_vec();
        let num_evals = advice_queries.len()
            + fixed_queries.len()
            + 1
            + cs.permutation().get_columns().len()
            + (3 * num_permutation_zs - 1)
            + 5 * cs.lookups().len();
        let num_phase = *cs.advice_column_phase().iter().max().unwrap_or(&0) as usize + 1;
        // Indices of advice and challenge are not same as their position in calldata/memory,
        // because we support multiple phases, we need to remap them and find their actual indices.
        let remapping = |phase: Vec<u8>| {
            let nums = phase.iter().fold(vec![0; num_phase], |mut nums, phase| {
                nums[*phase as usize] += 1;
                nums
            });
            let offsets = nums
                .iter()
                .take(num_phase - 1)
                .fold(vec![0], |mut offsets, n| {
                    offsets.push(offsets.last().unwrap() + n);
                    offsets
                });
            let index = phase
                .iter()
                .scan(offsets, |state, phase| {
                    let index = state[*phase as usize];
                    state[*phase as usize] += 1;
                    Some(index)
                })
                .collect::<Vec<_>>();
            (nums, index)
        };
        let (num_user_advices, advice_indices) = remapping(cs.advice_column_phase());
        let (num_user_challenges, challenge_indices) = remapping(cs.challenge_phase());
        let rotation_last = -(cs.blinding_factors() as i32 + 1);
        let num_rotations = chain![
            advice_queries.iter().map(|query| query.1),
            fixed_queries.iter().map(|query| query.1),
            (num_permutation_zs > 0)
                .then_some([0, 1])
                .into_iter()
                .flatten(),
            (num_permutation_zs > 1).then_some(rotation_last),
            (num_lookup_zs > 0)
                .then_some([-1, 0, 1])
                .into_iter()
                .flatten(),
        ]
        .unique()
        .count();
        Self {
            num_fixeds,
            permutation_columns,
            permutation_chunk_len,
            num_lookup_permuteds,
            num_permutation_zs,
            num_lookup_zs,
            num_quotients,
            advice_queries,
            fixed_queries,
            num_evals,
            num_rotations,
            num_user_advices,
            num_user_challenges,
            advice_indices,
            challenge_indices,
            rotation_last,
        }
    }

    pub(crate) fn num_advices(&self) -> Vec<usize> {
        chain![
            self.num_user_advices.iter().cloned(),
            (self.num_lookup_permuteds != 0).then_some(self.num_lookup_permuteds), // lookup permuted
            [
                self.num_permutation_zs + self.num_lookup_zs + 1, // permutation and lookup grand products, random
                self.num_quotients,                               // quotients
            ],
        ]
        .collect()
    }

    pub(crate) fn num_challenges(&self) -> Vec<usize> {
        let mut num_challenges = self.num_user_challenges.clone();
        // If there is no lookup used, merge also beta and gamma into the last user phase, to avoid
        // squeezing challenge from nothing.
        // Otherwise, merge theta into last user phase since they are originally adjacent.
        if self.num_lookup_permuteds == 0 {
            *num_challenges.last_mut().unwrap() += 3; // theta, beta, gamma
            num_challenges.extend([
                1, // y
                1, // x
            ]);
        } else {
            *num_challenges.last_mut().unwrap() += 1; // theta
            num_challenges.extend([
                2, // beta, gamma
                1, // y
                1, // x
            ]);
        }
        num_challenges
    }

    pub(crate) fn num_permutations(&self) -> usize {
        self.permutation_columns.len()
    }

    pub(crate) fn num_lookups(&self) -> usize {
        self.num_lookup_zs
    }

    pub(crate) fn proof_len(&self, scheme: BatchOpenScheme) -> usize {
        // Each G1 commitment in the proof is 128 bytes (EIP-2537 padded
        // BLS12-381 G1 = 4 words). Scalar evals stay at 32 bytes.
        self.num_advices().iter().sum::<usize>() * 0x80
            + self.num_evals * 0x20
            + self.batch_open_proof_len(scheme)
    }

    pub(crate) fn batch_open_proof_len(&self, scheme: BatchOpenScheme) -> usize {
        (match scheme {
            Bdfg21 => 2,
            Gwc19 => self.num_rotations,
        }) * 0x80
    }
}

#[derive(Debug)]
pub(crate) struct Data {
    pub(crate) challenge_mptr: Ptr,
    pub(crate) theta_mptr: Ptr,

    pub(crate) quotient_comm_cptr: Ptr,
    pub(crate) w_cptr: Ptr,

    pub(crate) fixed_comms: Vec<EcPoint>,
    pub(crate) permutation_comms: HashMap<Column<Any>, EcPoint>,
    pub(crate) advice_comms: Vec<EcPoint>,
    pub(crate) lookup_permuted_comms: Vec<(EcPoint, EcPoint)>,
    pub(crate) permutation_z_comms: Vec<EcPoint>,
    pub(crate) lookup_z_comms: Vec<EcPoint>,
    pub(crate) random_comm: EcPoint,

    pub(crate) challenges: Vec<Word>,

    pub(crate) instance_eval: Word,
    pub(crate) advice_evals: HashMap<(usize, i32), Word>,
    pub(crate) fixed_evals: HashMap<(usize, i32), Word>,
    pub(crate) random_eval: Word,
    pub(crate) permutation_evals: HashMap<Column<Any>, Word>,
    pub(crate) permutation_z_evals: Vec<(Word, Word, Word)>,
    pub(crate) lookup_evals: Vec<(Word, Word, Word, Word, Word)>,

    pub(crate) computed_quotient_comm: EcPoint,
    pub(crate) computed_quotient_eval: Word,
}

impl Data {
    pub(crate) fn new(
        meta: &ConstraintSystemMeta,
        vk: &Halo2VerifyingKey,
        vk_mptr: Ptr,
        proof_cptr: Ptr,
    ) -> Self {
        // BLS12-381 G1 commitments occupy 4 words (EIP-2537 padded), so the
        // stride between consecutive points is 4 instead of the BN254-era 2.
        let fixed_comm_mptr = vk_mptr + vk.constants.len();
        let permutation_comm_mptr = fixed_comm_mptr + 4 * vk.fixed_comms.len();
        let challenge_mptr = permutation_comm_mptr + 4 * vk.permutation_comms.len();
        let theta_mptr = challenge_mptr + meta.challenge_indices.len();

        let advice_comm_start = proof_cptr;
        let lookup_permuted_comm_start = advice_comm_start + 4 * meta.advice_indices.len();
        let permutation_z_comm_start = lookup_permuted_comm_start + 4 * meta.num_lookup_permuteds;
        let lookup_z_comm_start = permutation_z_comm_start + 4 * meta.num_permutation_zs;
        let random_comm_start = lookup_z_comm_start + 4 * meta.num_lookup_zs;
        let quotient_comm_start = random_comm_start + 4;

        let eval_cptr = quotient_comm_start + 4 * meta.num_quotients;
        let advice_eval_cptr = eval_cptr;
        let fixed_eval_cptr = advice_eval_cptr + meta.advice_queries.len();
        let random_eval_cptr = fixed_eval_cptr + meta.fixed_queries.len();
        let permutation_eval_cptr = random_eval_cptr + 1;
        let permutation_z_eval_cptr = permutation_eval_cptr + meta.num_permutations();
        let lookup_eval_cptr = permutation_z_eval_cptr + 3 * meta.num_permutation_zs - 1;
        let w_cptr = lookup_eval_cptr + 5 * meta.num_lookups();

        let fixed_comms = EcPoint::range(fixed_comm_mptr)
            .take(meta.num_fixeds)
            .collect();
        let permutation_comms = izip!(
            meta.permutation_columns.iter().cloned(),
            EcPoint::range(permutation_comm_mptr)
        )
        .collect();
        let advice_comms = meta
            .advice_indices
            .iter()
            .map(|idx| advice_comm_start + 4 * idx)
            .map_into()
            .collect();
        let lookup_permuted_comms = EcPoint::range(lookup_permuted_comm_start)
            .take(meta.num_lookup_permuteds)
            .tuples()
            .collect();
        let permutation_z_comms = EcPoint::range(permutation_z_comm_start)
            .take(meta.num_permutation_zs)
            .collect();
        let lookup_z_comms = EcPoint::range(lookup_z_comm_start)
            .take(meta.num_lookup_zs)
            .collect();
        let random_comm = random_comm_start.into();
        // BLS layout: the computed quotient lives in a contiguous 4-word
        // block starting at QUOTIENT_MPTR (x_hi, x_lo, y_hi, y_lo).
        let computed_quotient_comm = EcPoint::new(Ptr::memory("QUOTIENT_MPTR"));

        let challenges = meta
            .challenge_indices
            .iter()
            .map(|idx| challenge_mptr + *idx)
            .map_into()
            .collect_vec();
        let instance_eval = Ptr::memory("INSTANCE_EVAL_MPTR").into();
        let advice_evals = izip!(
            meta.advice_queries.iter().cloned(),
            Word::range(advice_eval_cptr)
        )
        .collect();
        let fixed_evals = izip!(
            meta.fixed_queries.iter().cloned(),
            Word::range(fixed_eval_cptr)
        )
        .collect();
        let random_eval = random_eval_cptr.into();
        let permutation_evals = izip!(
            meta.permutation_columns.iter().cloned(),
            Word::range(permutation_eval_cptr)
        )
        .collect();
        let permutation_z_evals = Word::range(permutation_z_eval_cptr)
            .take(3 * meta.num_permutation_zs)
            .tuples()
            .collect_vec();
        let lookup_evals = Word::range(lookup_eval_cptr)
            .take(5 * meta.num_lookup_zs)
            .tuples()
            .collect_vec();
        let computed_quotient_eval = Ptr::memory("QUOTIENT_EVAL_MPTR").into();

        Self {
            challenge_mptr,
            theta_mptr,
            quotient_comm_cptr: quotient_comm_start,
            w_cptr,

            fixed_comms,
            permutation_comms,
            advice_comms,
            lookup_permuted_comms,
            permutation_z_comms,
            lookup_z_comms,
            random_comm,
            computed_quotient_comm,

            challenges,

            instance_eval,
            advice_evals,
            fixed_evals,
            permutation_evals,
            permutation_z_evals,
            lookup_evals,
            random_eval,
            computed_quotient_eval,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Location {
    Calldata,
    Memory,
}

impl Location {
    fn opcode(&self) -> &'static str {
        match self {
            Location::Calldata => "calldataload",
            Location::Memory => "mload",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Value {
    /// Byte offset stored as signed so that the BLS code-gen can compute
    /// `ptr - N` even when `N` exceeds the original offset (the result
    /// only ever appears as `ptr_end` in `lt(ptr_end, ptr)` style loops
    /// where any value strictly less than the smallest visited address is
    /// acceptable).
    Integer(isize),
    /// A symbolic Yul identifier `name`, with an optional byte-offset that
    /// will be rendered as `add(name, 0xNN)` (or just `name` when zero).
    Identifier(&'static str, isize),
}

impl Value {
    pub(crate) fn is_integer(&self) -> bool {
        match self {
            Value::Integer(_) => true,
            Value::Identifier(..) => false,
        }
    }

    pub(crate) fn as_usize(&self) -> usize {
        match self {
            Value::Integer(int) => *int as usize,
            Value::Identifier(..) => unreachable!(),
        }
    }
}

impl Default for Value {
    fn default() -> Self {
        Self::Integer(0)
    }
}

impl From<&'static str> for Value {
    fn from(ident: &'static str) -> Self {
        Value::Identifier(ident, 0)
    }
}

impl From<usize> for Value {
    fn from(int: usize) -> Self {
        Value::Integer(int as isize)
    }
}

fn fmt_hex(off: isize) -> String {
    let hex = format!("{:x}", off as usize);
    if hex.len() % 2 == 1 {
        format!("0x0{hex}")
    } else {
        format!("0x{hex}")
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Value::Integer(int) if *int >= 0 => write!(f, "{}", fmt_hex(*int)),
            // Negative literal: render as `sub(0, +int)` to keep the EVM
            // expression syntactically valid inside Yul.
            Value::Integer(int) => write!(f, "sub(0, {})", fmt_hex(-*int)),
            Value::Identifier(ident, 0) => write!(f, "{ident}"),
            Value::Identifier(ident, off) if *off > 0 => {
                write!(f, "add({ident}, {})", fmt_hex(*off))
            }
            Value::Identifier(ident, off) => {
                write!(f, "sub({ident}, {})", fmt_hex(-*off))
            }
        }
    }
}

impl Add<usize> for Value {
    type Output = Value;

    fn add(self, rhs: usize) -> Self::Output {
        match self {
            Value::Integer(int) => Value::Integer(int + (rhs as isize) * 0x20),
            Value::Identifier(name, off) => {
                Value::Identifier(name, off + (rhs as isize) * 0x20)
            }
        }
    }
}

impl Sub<usize> for Value {
    type Output = Value;

    fn sub(self, rhs: usize) -> Self::Output {
        match self {
            Value::Integer(int) => Value::Integer(int - (rhs as isize) * 0x20),
            Value::Identifier(name, off) => {
                Value::Identifier(name, off - (rhs as isize) * 0x20)
            }
        }
    }
}

/// `Ptr` points to a EVM word at either calldata or memory.
///
/// When adding or subtracting it by 1, its value moves by 32 and points to next/previous EVM word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ptr {
    loc: Location,
    value: Value,
}

impl Ptr {
    pub(crate) fn new(loc: Location, value: impl Into<Value>) -> Self {
        Self {
            loc,
            value: value.into(),
        }
    }

    pub(crate) fn memory(value: impl Into<Value>) -> Self {
        Self::new(Location::Memory, value.into())
    }

    pub(crate) fn calldata(value: impl Into<Value>) -> Self {
        Self::new(Location::Calldata, value.into())
    }

    pub(crate) fn loc(&self) -> Location {
        self.loc
    }

    pub(crate) fn value(&self) -> Value {
        self.value
    }
}

impl Display for Ptr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl Add<usize> for Ptr {
    type Output = Ptr;

    fn add(mut self, rhs: usize) -> Self::Output {
        self.value = self.value + rhs;
        self
    }
}

impl Sub<usize> for Ptr {
    type Output = Ptr;

    fn sub(mut self, rhs: usize) -> Self::Output {
        self.value = self.value - rhs;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Word(Ptr);

impl Word {
    pub(crate) fn range(word: impl Into<Word>) -> impl Iterator<Item = Word> {
        let ptr = word.into().ptr();
        (0..).map(move |idx| ptr + idx).map_into()
    }

    pub(crate) fn ptr(&self) -> Ptr {
        self.0
    }

    pub(crate) fn loc(&self) -> Location {
        self.0.loc()
    }
}

impl Display for Word {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}({})", self.0.loc.opcode(), self.0.value)
    }
}

impl From<Ptr> for Word {
    fn from(ptr: Ptr) -> Self {
        Self(ptr)
    }
}

/// A G1 point in the EIP-2537 padded layout: four EVM words at
/// `(base + 0, base + 1, base + 2, base + 3)` carrying
/// `(x_hi, x_lo, y_hi, y_lo)` respectively. Each Fp coordinate is 64 bytes
/// (16 zero-byte prefix + 48 byte value), and `EcPoint::range` therefore
/// strides 4 words between consecutive points instead of the BN254-era 2.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct EcPoint {
    base: Ptr,
}

impl EcPoint {
    pub(crate) fn new(base: impl Into<Ptr>) -> Self {
        Self { base: base.into() }
    }

    /// Iterate G1 points starting at the given base, advancing by 4 words.
    pub(crate) fn range(base: impl Into<EcPoint>) -> impl Iterator<Item = EcPoint> {
        let base = base.into().base;
        (0..).map(move |idx| EcPoint::new(base + 4 * idx))
    }

    pub(crate) fn loc(&self) -> Location {
        self.base.loc()
    }

    /// Pointer to the first word of the point (= the `x_hi` slot).
    pub(crate) fn ptr(&self) -> Ptr {
        self.base
    }

    pub(crate) fn x_hi(&self) -> Word {
        Word::from(self.base)
    }
    pub(crate) fn x_lo(&self) -> Word {
        Word::from(self.base + 1)
    }
    pub(crate) fn y_hi(&self) -> Word {
        Word::from(self.base + 2)
    }
    pub(crate) fn y_lo(&self) -> Word {
        Word::from(self.base + 3)
    }

    /// Returns the four words (x_hi, x_lo, y_hi, y_lo) in EIP-2537 order.
    pub(crate) fn words(&self) -> [Word; 4] {
        [self.x_hi(), self.x_lo(), self.y_hi(), self.y_lo()]
    }
}

impl From<Ptr> for EcPoint {
    fn from(ptr: Ptr) -> Self {
        Self::new(ptr)
    }
}

/// Emit four `mstore`s copying a 4-word G1 point from `src` (in calldata or
/// memory) into the contiguous memory range starting at `dst_base`.
pub(crate) fn copy_g1_point(dst_base: Ptr, src: &EcPoint) -> [String; 4] {
    let [x_hi, x_lo, y_hi, y_lo] = src.words();
    [
        format!("mstore({}, {x_hi})", dst_base),
        format!("mstore({}, {x_lo})", dst_base + 1),
        format!("mstore({}, {y_hi})", dst_base + 2),
        format!("mstore({}, {y_lo})", dst_base + 3),
    ]
}

/// Add indention to given lines by `4 * N` spaces.
pub(crate) fn indent<const N: usize>(
    lines: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    lines
        .into_iter()
        .map(|line| format!("{}{}", " ".repeat(N * 4), line.into()))
        .collect()
}

/// Create a code block for given lines with indention.
///
/// If `PACKED` is true, single line code block will be packed into single line.
pub(crate) fn code_block<const N: usize, const PACKED: bool>(
    lines: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    let lines = lines.into_iter().map_into().collect_vec();
    let bracket_indent = " ".repeat((N - 1) * 4);
    match lines.len() {
        0 => vec![format!("{bracket_indent}{{}}")],
        1 if PACKED => vec![format!("{bracket_indent}{{ {} }}", lines[0])],
        _ => chain![
            [format!("{bracket_indent}{{")],
            indent::<N>(lines),
            [format!("{bracket_indent}}}")],
        ]
        .collect(),
    }
}

/// Create a for loop with proper indention.
pub(crate) fn for_loop(
    initialization: impl IntoIterator<Item = impl Into<String>>,
    condition: impl Into<String>,
    advancement: impl IntoIterator<Item = impl Into<String>>,
    body: impl IntoIterator<Item = impl Into<String>>,
) -> Vec<String> {
    chain![
        ["for".to_string()],
        code_block::<2, true>(initialization),
        indent::<1>([condition.into()]),
        code_block::<2, true>(advancement),
        code_block::<1, false>(body),
    ]
    .collect()
}

pub(crate) fn group_backward_adjacent_words<'a>(
    words: impl IntoIterator<Item = &'a Word>,
) -> Vec<(Location, Vec<&'a Word>)> {
    words.into_iter().fold(Vec::new(), |mut word_groups, word| {
        if let Some(last_group) = word_groups.last_mut() {
            let last_word = **last_group.1.last().unwrap();
            if last_group.0 == word.loc()
                && last_word.ptr().value().is_integer()
                && last_word.ptr() - 1 == word.ptr()
            {
                last_group.1.push(word)
            } else {
                word_groups.push((word.loc(), vec![word]))
            }
            word_groups
        } else {
            vec![(word.loc(), vec![word])]
        }
    })
}

pub(crate) fn group_backward_adjacent_ec_points<'a>(
    ec_point: impl IntoIterator<Item = &'a EcPoint>,
) -> Vec<(Location, Vec<&'a EcPoint>)> {
    // BLS12-381 EIP-2537 stride is 4 words per G1 point, so two points are
    // backward-adjacent when their bases differ by exactly 4 (one EcPoint
    // step).
    ec_point
        .into_iter()
        .fold(Vec::new(), |mut ec_point_groups, ec_point| {
            if let Some(last_group) = ec_point_groups.last_mut() {
                let last_ec_point = **last_group.1.last().unwrap();
                if last_group.0 == ec_point.loc()
                    && last_ec_point.ptr().value().is_integer()
                    && last_ec_point.ptr() - 4 == ec_point.ptr()
                {
                    last_group.1.push(ec_point)
                } else {
                    ec_point_groups.push((ec_point.loc(), vec![ec_point]))
                }
                ec_point_groups
            } else {
                vec![(ec_point.loc(), vec![ec_point])]
            }
        })
}

// ----------------------------------------------------------------------------
// BLS12-381 EIP-2537 encoding helpers.
//
// EIP-2537 encodes each Fp coordinate as 64 bytes: 16 leading zero bytes
// followed by 48 bytes of value (big-endian). A G1 point therefore occupies
// 128 bytes = 4 u256 words: (x_hi, x_lo, y_hi, y_lo) where hi has 16 zero
// MSBs. A G2 point occupies 256 bytes = 8 words; the c0/c1 ordering matches
// EIP-2537 (X.c0, X.c1, Y.c0, Y.c1).
//
// We provide two flavours of helper:
//   * `g1_to_u256s` / `g2_to_u256s` -- take *real* BLS12-381 curve points
//     (from halo2curves 0.7) and emit the proper EIP-2537 layout. These will
//     be used once a halo2 KZG-BLS prover backend is wired in.
//   * `bls_g1_pad_from_bn254_bytes` / `bls_g2_pad_from_bn254_bytes` -- take
//     a halo2_proofs v0.3 BN254 point and zero-extend its 32-byte coordinates
//     to 48 bytes before splitting. The resulting bytes are NOT valid BLS
//     curve points (different field, different curve equation); they exist
//     only so the BN254-flavoured codegen pipeline can keep producing
//     calldata-shape-correct Solidity verifiers.
// ----------------------------------------------------------------------------

/// Convert a 48-byte big-endian Fp limb into the EIP-2537 (hi, lo) split.
fn fp48_be_to_hi_lo(be: &[u8]) -> (U256, U256) {
    debug_assert_eq!(be.len(), 48);
    let mut hi_bytes = [0u8; 32];
    hi_bytes[16..].copy_from_slice(&be[..16]);
    let mut lo_bytes = [0u8; 32];
    lo_bytes.copy_from_slice(&be[16..]);
    (
        U256::from_be_bytes(hi_bytes),
        U256::from_be_bytes(lo_bytes),
    )
}

fn bn254_fq_to_be48(fe: &bn256::Fq) -> [u8; 48] {
    // BN254 Fq is 254 bits (32 bytes LE). To re-shape into the BLS12-381
    // 48-byte slot we left-pad with 16 zero bytes after big-endianifying.
    let le = fe.to_repr();
    let mut be32 = [0u8; 32];
    be32.copy_from_slice(le.as_ref());
    be32.reverse();
    let mut be48 = [0u8; 48];
    be48[16..].copy_from_slice(&be32);
    be48
}

/// Encode a BLS12-381 G1 point in EIP-2537 padded form (4 u256 words).
pub(crate) fn g1_to_u256s(ec_point: impl Borrow<bls12_381::G1Affine>) -> [U256; 4] {
    let coords = ec_point.borrow().coordinates().unwrap();
    let x_repr = coords.x().to_repr();
    let y_repr = coords.y().to_repr();
    let mut x_be = [0u8; 48];
    x_be.copy_from_slice(x_repr.as_ref());
    x_be.reverse();
    let mut y_be = [0u8; 48];
    y_be.copy_from_slice(y_repr.as_ref());
    y_be.reverse();
    let (x_hi, x_lo) = fp48_be_to_hi_lo(&x_be);
    let (y_hi, y_lo) = fp48_be_to_hi_lo(&y_be);
    [x_hi, x_lo, y_hi, y_lo]
}

/// Encode a BLS12-381 G2 point in EIP-2537 padded form (8 u256 words).
pub(crate) fn g2_to_u256s(ec_point: impl Borrow<bls12_381::G2Affine>) -> [U256; 8] {
    let coords = ec_point.borrow().coordinates().unwrap();
    // halo2curves 0.7 hides Fq2.c0 / Fq2.c1 behind a private field; use the
    // public `to_bytes()` helper which emits 96 LE bytes = (c0_le || c1_le).
    let x_bytes: [u8; 96] = coords.x().to_bytes();
    let y_bytes: [u8; 96] = coords.y().to_bytes();
    let to_be = |le: &[u8]| {
        let mut be = [0u8; 48];
        be.copy_from_slice(le);
        be.reverse();
        be
    };
    let xc0 = to_be(&x_bytes[..48]);
    let xc1 = to_be(&x_bytes[48..]);
    let yc0 = to_be(&y_bytes[..48]);
    let yc1 = to_be(&y_bytes[48..]);
    let (x0_hi, x0_lo) = fp48_be_to_hi_lo(&xc0);
    let (x1_hi, x1_lo) = fp48_be_to_hi_lo(&xc1);
    let (y0_hi, y0_lo) = fp48_be_to_hi_lo(&yc0);
    let (y1_hi, y1_lo) = fp48_be_to_hi_lo(&yc1);
    [x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo]
}

/// Shape-only conversion: takes a BN254 G1 point, zero-extends its 32-byte
/// coordinates to 48 bytes, and returns the EIP-2537 4-word layout. NOT a
/// valid BLS curve point.
pub(crate) fn bls_g1_pad_from_bn254_bytes(
    ec_point: impl Borrow<bn256::G1Affine>,
) -> [U256; 4] {
    let coords = ec_point.borrow().coordinates().unwrap();
    let x_be = bn254_fq_to_be48(coords.x());
    let y_be = bn254_fq_to_be48(coords.y());
    let (x_hi, x_lo) = fp48_be_to_hi_lo(&x_be);
    let (y_hi, y_lo) = fp48_be_to_hi_lo(&y_be);
    [x_hi, x_lo, y_hi, y_lo]
}

/// Shape-only conversion: takes a BN254 G2 point and produces the EIP-2537
/// 8-word layout. See `bls_g1_pad_from_bn254_bytes` for caveats.
pub(crate) fn bls_g2_pad_from_bn254_bytes(
    ec_point: impl Borrow<bn256::G2Affine>,
) -> [U256; 8] {
    let coords = ec_point.borrow().coordinates().unwrap();
    // halo2curves 0.6 bn256::Fq2 has c0/c1; EIP-2537 expects c0 first.
    let xc0 = bn254_fq_to_be48(&coords.x().c0);
    let xc1 = bn254_fq_to_be48(&coords.x().c1);
    let yc0 = bn254_fq_to_be48(&coords.y().c0);
    let yc1 = bn254_fq_to_be48(&coords.y().c1);
    let (x0_hi, x0_lo) = fp48_be_to_hi_lo(&xc0);
    let (x1_hi, x1_lo) = fp48_be_to_hi_lo(&xc1);
    let (y0_hi, y0_lo) = fp48_be_to_hi_lo(&yc0);
    let (y1_hi, y1_lo) = fp48_be_to_hi_lo(&yc1);
    [x0_hi, x0_lo, x1_hi, x1_lo, y0_hi, y0_lo, y1_hi, y1_lo]
}

/// Legacy BN254 G1 helper kept for callers that still want the 2-word layout.
pub(crate) fn bn256_g1_to_u256s(ec_point: impl Borrow<bn256::G1Affine>) -> [U256; 2] {
    let coords = ec_point.borrow().coordinates().unwrap();
    [coords.x(), coords.y()].map(fq_to_u256)
}

pub(crate) fn fq_to_u256(fe: impl Borrow<bn256::Fq>) -> U256 {
    fe_to_u256(fe)
}

pub(crate) fn fr_to_u256(fe: impl Borrow<bn256::Fr>) -> U256 {
    fe_to_u256(fe)
}

pub(crate) fn fe_to_u256<F>(fe: impl Borrow<F>) -> U256
where
    F: PrimeField<Repr = [u8; 0x20]>,
{
    U256::from_le_bytes(fe.borrow().to_repr())
}

pub(crate) fn to_u256_be_bytes<T>(value: T) -> [u8; 32]
where
    U256: UintTryFrom<T>,
{
    U256::from(value).to_be_bytes()
}
