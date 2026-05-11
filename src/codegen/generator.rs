use super::*;

impl<'a> SolidityGenerator<'a> {
    const SUPPORTED_COMMITTED_INSTANCE_COLUMNS: usize = 1;
    const SUPPORTED_NON_COMMITTED_INSTANCE_COLUMNS: usize = 1;
    const QUOTIENT_FIXED_STATE_WORDS: usize = 2;
    /// Committed-instance commitment policy hard-coded by the generated
    /// verifier ABI.
    pub const SUPPORTED_COMMITTED_INSTANCE_COMMITMENT: CommittedInstanceCommitmentKind =
        CommittedInstanceCommitmentKind::Identity;

    /// Return a new `SolidityGenerator`.
    pub fn new(
        params: &'a ParamsKZG<Bls12>,
        vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        num_instances: usize,
        num_committed_instances: usize,
    ) -> Self {
        Self::try_new(params, vk, num_instances, num_committed_instances)
            .unwrap_or_else(|err| panic!("unsupported Solidity verifier shape: {err}"))
    }

    /// Try to construct a new `SolidityGenerator`, returning a typed error
    /// when the supplied constraint system is outside the currently supported
    /// Midfall verifier shape.
    pub fn try_new(
        params: &'a ParamsKZG<Bls12>,
        vk: &'a VerifyingKey<Fq, KZGCommitmentScheme<Bls12>>,
        num_instances: usize,
        num_committed_instances: usize,
    ) -> Result<Self, GeneratorError> {
        if vk.cs().num_advice_columns() == 0 {
            return Err(GeneratorError::NoAdviceColumns);
        }
        // Midfall's Rust verifier receives instances in two arguments:
        // committed instances and normal (non-committed) instances. The
        // total number of instance columns is their sum, with committed
        // columns first in verifier order (`plonk/verifier.rs::verify_proof`).
        Self::validate_instance_column_shape(
            vk.cs().num_instance_columns(),
            num_committed_instances,
        )?;
        if let Some((column, rotation)) = vk
            .cs()
            .instance_queries()
            .iter()
            .find(|(_, rotation)| *rotation != Rotation::cur())
        {
            return Err(GeneratorError::RotatedInstanceQuery {
                column: column.index(),
                rotation: rotation.0,
            });
        }

        let meta = ConstraintSystemMeta::new(vk.cs(), num_committed_instances);

        Ok(Self {
            params,
            vk,
            num_instances,
            num_committed_instances,
            acc_encoding: None,
            meta,
        })
    }

    /// Set `AccumulatorEncoding`.
    ///
    /// This is the panic-on-error convenience form. Use
    /// [`Self::try_set_acc_encoding`] when caller-controlled public-input
    /// layouts should produce a typed [`GeneratorError`] instead.
    pub fn set_acc_encoding(self, acc_encoding: Option<AccumulatorEncoding>) -> Self {
        self.try_set_acc_encoding(acc_encoding)
            .unwrap_or_else(|err| panic!("unsupported accumulator encoding: {err}"))
    }

    /// Try to enable or disable the optional public-accumulator pairing batch.
    ///
    /// When enabled, the accumulator must be a tail of the public-input vector
    /// and must use the currently supported Midnight BLS12-381 limb packing.
    pub fn try_set_acc_encoding(
        mut self,
        acc_encoding: Option<AccumulatorEncoding>,
    ) -> Result<Self, GeneratorError> {
        if let Some(acc_encoding) = acc_encoding {
            acc_encoding.validate_for_num_instances(self.num_instances)?;
        }
        self.acc_encoding = acc_encoding;
        Ok(self)
    }

    /// Number of instance columns committed to in the transcript (vs read
    /// from `instances` and Lagrange-interpolated locally). Surfacing the
    /// value here so that downstream callers (drivers, debugging
    /// examples) can configure committed-instance proofs without having
    /// to plumb through a constructor argument.
    ///
    /// Prefer passing the committed-column count to [`Self::new`] /
    /// [`Self::try_new`]. This setter is retained for older call sites, but
    /// it validates the exact same supported protocol shape before updating
    /// metadata.
    pub fn set_num_committed_instances(mut self, n: usize) -> Self {
        Self::validate_instance_column_shape(self.vk.cs().num_instance_columns(), n)
            .unwrap_or_else(|err| panic!("unsupported Solidity verifier shape: {err}"));
        self.num_committed_instances = n;
        self.meta = ConstraintSystemMeta::new(self.vk.cs(), n);
        self
    }

    /// Return the committed-instance commitment policy for this generator.
    pub fn committed_instance_commitment_kind(&self) -> CommittedInstanceCommitmentKind {
        Self::SUPPORTED_COMMITTED_INSTANCE_COMMITMENT
    }

    /// Validate the currently supported committed/non-committed instance split.
    fn validate_instance_column_shape(
        total_instance_columns: usize,
        num_committed_instances: usize,
    ) -> Result<(), GeneratorError> {
        // The Rust verifier accepts committed and normal instance arguments
        // separately, with committed instance columns first. The current
        // Solidity calldata ABI supports exactly one identity-committed column
        // and one direct public-input column, so every instance query can be
        // classified without an extra column-routing table or supplied
        // committed-instance commitment.
        let supported_committed = Self::SUPPORTED_COMMITTED_INSTANCE_COLUMNS;
        let supported_non_committed = Self::SUPPORTED_NON_COMMITTED_INSTANCE_COLUMNS;
        let non_committed = total_instance_columns
            .checked_sub(num_committed_instances)
            .unwrap_or(usize::MAX);

        if num_committed_instances != supported_committed
            || non_committed != supported_non_committed
        {
            return Err(GeneratorError::UnsupportedInstanceColumnShape {
                total: total_instance_columns,
                committed: num_committed_instances,
                expected_committed: supported_committed,
                expected_non_committed: supported_non_committed,
            });
        }

        Ok(())
    }

    /// Return the exact field-evaluation counts for the proof layout consumed
    /// by the generated Solidity verifier.
    pub fn proof_evaluation_counts(&self) -> ProofEvaluationCounts {
        let proof_cptr = Ptr::calldata(layout::abi::VERIFY_PROOF_PROOF_CPTR);
        let vk = self.generate_vk();
        let (_, meta, _, _) = self.meta_data_for_stable_static_layout(&vk, proof_cptr);

        let committed_instance = meta
            .instance_queries
            .iter()
            .filter(|(col, _)| *col < meta.num_committed_instances)
            .count();
        let computed_instance = meta.instance_queries.len() - committed_instance;
        let permutation_product = if meta.num_permutation_zs == 0 {
            0
        } else {
            3 * meta.num_permutation_zs - 1
        };
        let lookup_helper = meta.lookup_chunks.iter().sum();

        let counts = ProofEvaluationCounts {
            committed_instance,
            computed_instance,
            advice: meta.advice_queries.len(),
            // Fixed evals are query-based proof reads. The Rust verifier
            // reads the non-simple fixed queries that appear in
            // `protocol.proof.evals`; simple selector columns are synthesized
            // locally and feed selector buckets instead of proof scalars.
            fixed: meta
                .protocol
                .proof
                .evals
                .iter()
                .filter(|eval| matches!(eval, protocol::EvalRead::Fixed(_)))
                .count(),
            simple_selector_fixed: meta.num_simple_selectors,
            permutation_common: meta.permutation_columns.len(),
            permutation_product,
            permutation_sets: meta.num_permutation_zs,
            lookup_multiplicity: meta.num_lookups,
            lookup_helper,
            lookup_accumulator: 2 * meta.num_lookups,
            trash: meta.num_trashcans,
            dummy: meta.num_dummy_evals,
        };

        assert_eq!(
            counts.proof_total(),
            meta.num_evals,
            "proof evaluation count accounting must match verifier proof layout"
        );
        counts
    }

    /// Return a stable host-side manifest of quotient numerator identities.
    ///
    /// This diagnostic API follows the same source ordering as the generated
    /// quotient evaluator: normal gates, permutation, lookup, then trash.
    pub fn quotient_identity_manifest(&self) -> QuotientIdentityManifest {
        self.quotient_identity_manifest_for_meta(&self.meta)
    }

    fn quotient_identity_manifest_for_meta(
        &self,
        meta: &ConstraintSystemMeta,
    ) -> QuotientIdentityManifest {
        let mut simple_selector_cols: Vec<usize> =
            meta.simple_selector_cols.iter().copied().collect();
        simple_selector_cols.sort_unstable();

        let mut entries = Vec::new();
        let mut global_index = 0usize;
        for (gate_index, gate) in self.vk.cs().gates().iter().enumerate() {
            let target = gate
                .queried_selectors()
                .iter()
                .find(|selector| selector.is_simple())
                .map(|selector| {
                    let selector_index = simple_selector_cols
                        .iter()
                        .position(|fixed| *fixed == selector.index())
                        .expect("simple selector fixed column present");
                    QuotientIdentityManifestTarget::Selector {
                        selector_index,
                        fixed_column: selector.index(),
                    }
                })
                .unwrap_or(QuotientIdentityManifestTarget::Main);

            for polynomial_index in 0..gate.polynomials().len() {
                entries.push(QuotientIdentityManifestEntry {
                    global_index,
                    source: QuotientIdentitySource::Gate {
                        gate_index,
                        gate_name: gate.name().to_string(),
                        constraint_index: polynomial_index,
                        constraint_name: gate.constraint_name(polynomial_index).to_string(),
                        polynomial_index,
                    },
                    target,
                });
                global_index += 1;
            }
        }

        for identity_index in 0..meta.protocol.quotient.permutation {
            entries.push(QuotientIdentityManifestEntry {
                global_index,
                source: QuotientIdentitySource::Permutation { identity_index },
                target: QuotientIdentityManifestTarget::Main,
            });
            global_index += 1;
        }

        for identity_index in 0..meta.protocol.quotient.lookup {
            let (lookup_index, _) = meta
                .protocol
                .lookup_identity_source(identity_index)
                .expect("lookup identity index covered by protocol lookup chunks");
            let lookup_name = format!("lookup_{lookup_index}");
            entries.push(QuotientIdentityManifestEntry {
                global_index,
                source: QuotientIdentitySource::Lookup {
                    identity_index,
                    lookup_index,
                    lookup_name,
                },
                target: QuotientIdentityManifestTarget::Main,
            });
            global_index += 1;
        }

        for trash_index in 0..meta.protocol.quotient.trash {
            let trash_name = self.trash_manifest_name(trash_index);
            entries.push(QuotientIdentityManifestEntry {
                global_index,
                source: QuotientIdentitySource::Trash {
                    trash_index,
                    trash_name,
                },
                target: QuotientIdentityManifestTarget::Main,
            });
            global_index += 1;
        }

        QuotientIdentityManifest {
            entries,
            gate_identities: meta.protocol.quotient.gates,
            permutation_identities: meta.protocol.quotient.permutation,
            lookup_identities: meta.protocol.quotient.lookup,
            trash_identities: meta.protocol.quotient.trash,
            simple_selector_cols,
        }
    }

    fn trash_manifest_name(&self, trash_index: usize) -> String {
        // Additive-selector `create_gate` calls still leave a zero-polynomial
        // gate record in `cs.gates()`. The trash argument name itself is built
        // from constraint names and can be just separators for unnamed
        // constraints, so prefer the source gate name for diagnostics.
        if let Some(gate) = self
            .vk
            .cs()
            .gates()
            .iter()
            .filter(|gate| gate.polynomials().is_empty())
            .nth(trash_index)
        {
            return gate.name().to_string();
        }

        self.vk
            .cs()
            .trashcans()
            .get(trash_index)
            .map(|trash| trash.name().to_string())
            .unwrap_or_else(|| format!("trash_{trash_index}"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct QuotientStateSlots {
    // Persistent VM state words stored after the optional CSE temp area. The
    // Yul interpreter and native callbacks all share these addresses so inline
    // prefixes, bytecode identities, and callbacks advance the same y-batch.
    eval_numer_mptr: usize,
    trace_id_mptr: usize,
    selector_power_mptr: usize,
}

impl QuotientStateSlots {
    /// Place persistent VM state immediately after optional CSE temp words.
    fn new(tmp_mptr: usize, cse_temps: usize) -> Self {
        // Layout at `quotient_tmp_mptr`:
        //   [0 .. cse_temps)        VM STORE_TEMP/PUSH_TEMP scratch
        //   [cse_temps .. +2 words) accumulator and trace-id state
        //   [after state]           optional y^k selector power table
        //
        // Keeping state after CSE temps lets the same template work whether
        // VM CSE is enabled or not.
        let base = tmp_mptr + cse_temps * WORD_BYTES;
        Self {
            eval_numer_mptr: base,
            trace_id_mptr: base + WORD_BYTES,
            selector_power_mptr: base + 2 * WORD_BYTES,
        }
    }
}

#[derive(Clone, Debug)]
struct NativeGateCandidate {
    gate_idx: usize,
    vm_bytes: usize,
    native_bytes: usize,
    gas_saved: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NativeGateSelectionState {
    gas_saved: u64,
    native_bytes: usize,
    gate_indices: Vec<usize>,
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;

    #[test]
    fn instance_column_shape_validation_is_exact() {
        assert!(SolidityGenerator::validate_instance_column_shape(2, 1).is_ok());

        for (total, committed) in [(2, 0), (2, 2), (1, 1), (3, 1)] {
            assert!(
                matches!(
                    SolidityGenerator::validate_instance_column_shape(total, committed),
                    Err(GeneratorError::UnsupportedInstanceColumnShape { .. })
                ),
                "shape total={total}, committed={committed} should be rejected"
            );
        }
    }

    #[test]
    fn quotient_stack_words_cover_native_callback_scratch() {
        let build = QuotientProgramBuild {
            bytes: Vec::new(),
            consts: Vec::new(),
            max_stack: 3,
            packed32: false,
            cse_temps: 0,
            used_ops: Vec::new(),
            used_mem_tokens: Vec::new(),
        };

        assert_eq!(
            SolidityGenerator::quotient_stack_words_for_build(&build, 0),
            3
        );
        assert_eq!(
            SolidityGenerator::quotient_stack_words_for_build(&build, 2),
            3
        );
        assert_eq!(
            SolidityGenerator::quotient_stack_words_for_build(&build, 8),
            8
        );
    }

    #[test]
    fn native_gate_knapsack_prefers_gas_under_byte_budget() {
        let candidates = vec![
            NativeGateCandidate {
                gate_idx: 0,
                vm_bytes: 100,
                native_bytes: 320,
                gas_saved: 100,
            },
            NativeGateCandidate {
                gate_idx: 1,
                vm_bytes: 80,
                native_bytes: 160,
                gas_saved: 60,
            },
            NativeGateCandidate {
                gate_idx: 2,
                vm_bytes: 70,
                native_bytes: 160,
                gas_saved: 55,
            },
        ];

        let selection = SolidityGenerator::select_native_gate_candidates(&candidates, 2, 320);
        assert_eq!(selection.gate_indices, vec![1, 2]);
        assert_eq!(selection.gas_saved, 115);
        assert_eq!(selection.native_bytes, 320);
    }

    #[test]
    fn native_gate_default_budget_preserves_old_top_n_byte_envelope() {
        let candidates = vec![
            NativeGateCandidate {
                gate_idx: 0,
                vm_bytes: 100,
                native_bytes: 300,
                gas_saved: 1,
            },
            NativeGateCandidate {
                gate_idx: 1,
                vm_bytes: 80,
                native_bytes: 200,
                gas_saved: 1,
            },
            NativeGateCandidate {
                gate_idx: 2,
                vm_bytes: 70,
                native_bytes: 100,
                gas_saved: 1,
            },
        ];

        assert_eq!(
            SolidityGenerator::default_native_gate_byte_budget(&candidates, 2),
            500
        );
    }
}

impl<'a> SolidityGenerator<'a> {
    /// Render `Halo2Verifier.sol` with verifying key embedded into writer.
    ///
    /// The default render path emits trace/log branches when the crate
    /// is compiled with `--features solidity-trace`, and LOG1 gas
    /// checkpoints when compiled with `--features
    /// solidity-gas-checkpoints`.
    pub fn render_into(&self, verifier_writer: &mut impl fmt::Write) -> Result<(), fmt::Error> {
        self.generate_verifier(
            false,
            crate::SOLIDITY_TRACE_ENABLED,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            false,
            None,
        )
        .render(verifier_writer)
    }

    /// Render `Halo2Verifier.sol` with verifying key embedded and return it as `String`.
    pub fn render(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render a trace-enabled `Halo2Verifier.sol` with verifying key embedded into writer.
    pub fn render_trace_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            false,
            true,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            false,
            None,
        )
        .render(verifier_writer)
    }

    /// Render a trace-enabled `Halo2Verifier.sol` with verifying key embedded and return it as a
    /// `String`.
    pub fn render_trace(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_trace_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` (with VK
    /// embedded) into writer. Emits LOG1 events at section boundaries
    /// regardless of the `solidity-gas-checkpoints` feature flag.
    pub fn render_with_gas_checkpoints_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(false, crate::SOLIDITY_TRACE_ENABLED, true, false, None)
            .render(verifier_writer)
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` (with VK
    /// embedded) and return it as `String`.
    pub fn render_with_gas_checkpoints(&self) -> Result<String, fmt::Error> {
        let mut verifier_output = String::new();
        self.render_with_gas_checkpoints_into(&mut verifier_output)?;
        Ok(verifier_output)
    }

    /// Render `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` into writers.
    ///
    /// The default render path emits trace/log branches when the crate
    /// is compiled with `--features solidity-trace`, and LOG1 gas
    /// checkpoints when compiled with `--features
    /// solidity-gas-checkpoints`.
    pub fn render_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            crate::SOLIDITY_TRACE_ENABLED,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            false,
            None,
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` and return them as `String`.
    pub fn render_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    /// Render `Halo2Verifier.sol`, `Halo2VerifyingKey.sol`, and a linked
    /// `Halo2QuotientEvaluator.sol`.
    ///
    /// External quotient evaluators are correctness-critical. Production
    /// callers must first render/compile/deploy the quotient evaluator, then
    /// call [`Self::render_separately_with_pinned_quotient_into`] with its runtime
    /// length and codehash.
    #[deprecated(
        note = "external quotient evaluators must be pinned; use render_quotient_evaluator_into + render_separately_with_pinned_quotient_into"
    )]
    pub fn render_separately_with_quotient_into(
        &self,
        _verifier_writer: &mut impl fmt::Write,
        _vk_writer: &mut impl fmt::Write,
        _quotient_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        panic!(
            "external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first, compile/deploy it, then call \
             render_separately_with_pinned_quotient_into"
        );
    }

    /// Render `Halo2Verifier.sol`, `Halo2VerifyingKey.sol`, and
    /// `Halo2QuotientEvaluator.sol` and return them as `String`s.
    #[deprecated(
        note = "external quotient evaluators must be pinned; use render_quotient_evaluator + render_separately_with_pinned_quotient"
    )]
    pub fn render_separately_with_quotient(&self) -> Result<(String, String, String), fmt::Error> {
        panic!(
            "external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first, compile/deploy it, then call \
             render_separately_with_pinned_quotient"
        );
    }

    /// Render a trace-enabled `Halo2Verifier.sol`, `Halo2VerifyingKey.sol`,
    /// and linked `Halo2QuotientEvaluator.sol`.
    ///
    /// External quotient evaluators must be pinned even in trace builds.
    /// Use [`Self::render_trace_separately_with_pinned_quotient_into`].
    #[deprecated(
        note = "external quotient evaluators must be pinned; use render_trace_separately_with_pinned_quotient_into"
    )]
    pub fn render_trace_separately_with_quotient_into(
        &self,
        _verifier_writer: &mut impl fmt::Write,
        _vk_writer: &mut impl fmt::Write,
        _quotient_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        panic!(
            "trace external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first, compile/deploy it, then call \
             render_trace_separately_with_pinned_quotient_into"
        );
    }

    /// Render a trace-enabled split verifier/VK/quotient trio and return
    /// them as `String`s.
    #[deprecated(
        note = "external quotient evaluators must be pinned; use render_trace_separately_with_pinned_quotient"
    )]
    pub fn render_trace_separately_with_quotient(
        &self,
    ) -> Result<(String, String, String), fmt::Error> {
        panic!(
            "trace external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first, compile/deploy it, then call \
             render_trace_separately_with_pinned_quotient"
        );
    }

    /// Render only `Halo2QuotientEvaluator.sol`. Production deployment
    /// tooling can compile/deploy this first, compute its runtime length and
    /// codehash, then render a verifier with
    /// [`Self::render_separately_with_pinned_quotient_into`].
    pub fn render_quotient_evaluator_into(
        &self,
        quotient_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_quotient_evaluator(false)
            .render(quotient_writer)
    }

    /// Render only `Halo2QuotientEvaluator.sol` and return it as a `String`.
    pub fn render_quotient_evaluator(&self) -> Result<String, fmt::Error> {
        let mut quotient_output = String::new();
        self.render_quotient_evaluator_into(&mut quotient_output)?;
        Ok(quotient_output)
    }

    /// Render a trace-enabled `Halo2QuotientEvaluator.sol`.
    pub fn render_trace_quotient_evaluator_into(
        &self,
        quotient_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_quotient_evaluator(true)
            .render(quotient_writer)
    }

    /// Render a trace-enabled `Halo2QuotientEvaluator.sol` and return it as a
    /// `String`.
    pub fn render_trace_quotient_evaluator(&self) -> Result<String, fmt::Error> {
        let mut quotient_output = String::new();
        self.render_trace_quotient_evaluator_into(&mut quotient_output)?;
        Ok(quotient_output)
    }

    /// Render `Halo2Verifier.sol`, `Halo2VerifyingKey.sol`, and
    /// `Halo2QuotientEvaluator.sol`, with the verifier hard-pinned to the
    /// supplied quotient evaluator runtime length and codehash.
    pub fn render_separately_with_pinned_quotient_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
        quotient_writer: &mut impl fmt::Write,
        expected_quotient_len: usize,
        expected_quotient_codehash: U256,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            crate::SOLIDITY_TRACE_ENABLED,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            true,
            Some((expected_quotient_len, expected_quotient_codehash)),
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        self.generate_quotient_evaluator(crate::SOLIDITY_TRACE_ENABLED)
            .render(quotient_writer)?;
        Ok(())
    }

    /// Render the separated verifier/VK/quotient sources with a hard-pinned
    /// quotient evaluator.
    pub fn render_separately_with_pinned_quotient(
        &self,
        expected_quotient_len: usize,
        expected_quotient_codehash: U256,
    ) -> Result<(String, String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        let mut quotient_output = String::new();
        self.render_separately_with_pinned_quotient_into(
            &mut verifier_output,
            &mut vk_output,
            &mut quotient_output,
            expected_quotient_len,
            expected_quotient_codehash,
        )?;
        Ok((verifier_output, vk_output, quotient_output))
    }

    /// Render a trace-enabled separated verifier/VK/quotient trio with the
    /// verifier hard-pinned to the supplied quotient evaluator runtime length
    /// and codehash.
    pub fn render_trace_separately_with_pinned_quotient_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
        quotient_writer: &mut impl fmt::Write,
        expected_quotient_len: usize,
        expected_quotient_codehash: U256,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            true,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            true,
            Some((expected_quotient_len, expected_quotient_codehash)),
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        self.generate_quotient_evaluator(true)
            .render(quotient_writer)?;
        Ok(())
    }

    /// Render a trace-enabled separated verifier/VK/quotient trio with a
    /// hard-pinned quotient evaluator.
    pub fn render_trace_separately_with_pinned_quotient(
        &self,
        expected_quotient_len: usize,
        expected_quotient_codehash: U256,
    ) -> Result<(String, String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        let mut quotient_output = String::new();
        self.render_trace_separately_with_pinned_quotient_into(
            &mut verifier_output,
            &mut vk_output,
            &mut quotient_output,
            expected_quotient_len,
            expected_quotient_codehash,
        )?;
        Ok((verifier_output, vk_output, quotient_output))
    }

    /// Render a trace-enabled `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` into writers.
    pub fn render_trace_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(
            true,
            true,
            crate::SOLIDITY_GAS_CHECKPOINTS_ENABLED,
            false,
            None,
        )
        .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render a trace-enabled `Halo2Verifier.sol` and `Halo2VerifyingKey.sol` and return them as
    /// `String`s.
    pub fn render_trace_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_trace_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` and
    /// `Halo2VerifyingKey.sol` into writers. Emits LOG1 events at
    /// section boundaries regardless of the
    /// `solidity-gas-checkpoints` feature flag.
    pub fn render_with_gas_checkpoints_separately_into(
        &self,
        verifier_writer: &mut impl fmt::Write,
        vk_writer: &mut impl fmt::Write,
    ) -> Result<(), fmt::Error> {
        self.generate_verifier(true, crate::SOLIDITY_TRACE_ENABLED, true, false, None)
            .render(verifier_writer)?;
        self.generate_vk().render(vk_writer)?;
        Ok(())
    }

    /// Render a gas-checkpoint-enabled `Halo2Verifier.sol` and
    /// `Halo2VerifyingKey.sol` and return them as `String`s.
    pub fn render_with_gas_checkpoints_separately(&self) -> Result<(String, String), fmt::Error> {
        let mut verifier_output = String::new();
        let mut vk_output = String::new();
        self.render_with_gas_checkpoints_separately_into(&mut verifier_output, &mut vk_output)?;
        Ok((verifier_output, vk_output))
    }

    /// Generate the VK payload before compact quotient constants/program data.
    fn generate_base_vk(&self) -> Halo2VerifyingKey {
        let constants: Vec<(&'static str, U256)>;
        {
            use layout::VkHeaderSlot as Slot;

            let domain = self.vk.get_domain();
            // BLS12-381 scalar Fq is 32 bytes wide (256 bits) so the same
            // little-endian-to-u256 conversion that worked for BN254 Fr
            // also works here: the verifier reads each scalar from
            // calldata into a single 32-byte word.
            // `plonk/verifier.rs` hashes the verifying key into the
            // transcript before reading prover data. The Solidity template
            // absorbs this `transcript_repr` digest as its first transcript
            // word to preserve the Rust verifier's Fiat-Shamir prefix.
            let vk_digest = fe_to_u256::<Fq>(&self.vk.transcript_repr());
            let num_instances = U256::from(self.num_instances);
            let k = U256::from(domain.k());
            let n_inv = fe_to_u256::<Fq>(&Fq::from(1u64 << domain.k()).invert().unwrap());
            let omega = fe_to_u256::<Fq>(&domain.get_omega());
            let omega_inv = fe_to_u256::<Fq>(&domain.get_omega_inv());
            let omega_inv_to_l = {
                let l = self.meta.rotation_last.unsigned_abs() as u64;
                fe_to_u256::<Fq>(&domain.get_omega_inv().pow_vartime([l]))
            };
            let has_accumulator = U256::from(self.acc_encoding.is_some() as usize);
            let acc_offset = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.offset))
                .unwrap_or_default();
            let num_acc_limbs = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.num_limbs))
                .unwrap_or_default();
            let num_acc_limb_bits = self
                .acc_encoding
                .map(|acc_encoding| U256::from(acc_encoding.num_limb_bits))
                .unwrap_or_default();
            // EIP-2537 padded encodings come from `g1_to_u256s` / `g2_to_u256s`
            // (4 / 8 u256 words respectively). We cannot read `params.g[0]`
            // directly (the field is crate-private in midnight-proofs), so
            // we use the canonical BLS12-381 generator.
            let g1_pt: G1Affine = G1Affine::generator();
            let g2_pt: G2Affine = self.params.g2().to_affine();
            let neg_s_g2_pt: G2Affine = (-self.params.s_g2()).to_affine();
            let g1 = g1_to_u256s(g1_pt);
            let g2 = g2_to_u256s(g2_pt);
            let neg_s_g2 = g2_to_u256s(neg_s_g2_pt);

            let mut header = layout::VkHeaderLayout::builder();
            header
                .scalar(Slot::VkDigest, "vk_digest", vk_digest)
                .unwrap();
            header
                .scalar(Slot::NumInstances, "num_instances", num_instances)
                .unwrap();
            header.scalar(Slot::K, "k", k).unwrap();
            header.scalar(Slot::NInv, "n_inv", n_inv).unwrap();
            header.scalar(Slot::Omega, "omega", omega).unwrap();
            header
                .scalar(Slot::OmegaInv, "omega_inv", omega_inv)
                .unwrap();
            header
                .scalar(Slot::OmegaInvToL, "omega_inv_to_l", omega_inv_to_l)
                .unwrap();
            header
                .scalar(Slot::HasAccumulator, "has_accumulator", has_accumulator)
                .unwrap();
            header
                .scalar(Slot::AccOffset, "acc_offset", acc_offset)
                .unwrap();
            header
                .scalar(Slot::NumAccLimbs, "num_acc_limbs", num_acc_limbs)
                .unwrap();
            header
                .scalar(Slot::NumAccLimbBits, "num_acc_limb_bits", num_acc_limb_bits)
                .unwrap();
            header
                .g1(
                    Slot::G1Base,
                    ["g1_x_hi", "g1_x_lo", "g1_y_hi", "g1_y_lo"],
                    g1,
                )
                .unwrap();
            header
                .g2(
                    Slot::G2Base,
                    [
                        "g2_x_c0_hi",
                        "g2_x_c0_lo",
                        "g2_x_c1_hi",
                        "g2_x_c1_lo",
                        "g2_y_c0_hi",
                        "g2_y_c0_lo",
                        "g2_y_c1_hi",
                        "g2_y_c1_lo",
                    ],
                    g2,
                )
                .unwrap();
            header
                .g2(
                    Slot::NegSG2Base,
                    [
                        "neg_s_g2_x_c0_hi",
                        "neg_s_g2_x_c0_lo",
                        "neg_s_g2_x_c1_hi",
                        "neg_s_g2_x_c1_lo",
                        "neg_s_g2_y_c0_hi",
                        "neg_s_g2_y_c0_lo",
                        "neg_s_g2_y_c1_hi",
                        "neg_s_g2_y_c1_lo",
                    ],
                    neg_s_g2,
                )
                .unwrap();
            constants = header
                .finish()
                .unwrap_or_else(|err| panic!("invalid VK header layout: {err}"));
        }

        // Convert each commitment from G1Projective to G1Affine before
        // EIP-2537 packing.
        let to_affine = |g: &G1Projective| -> G1Affine { g.to_affine() };
        let fixed_comms: Vec<_> = chain![self.vk.fixed_commitments()]
            .map(to_affine)
            .map(g1_to_u256s)
            .map(|[a, b, c, d]| (a, b, c, d))
            .collect();
        let permutation_comms: Vec<_> = chain![self.vk.permutation().commitments()]
            .map(to_affine)
            .map(g1_to_u256s)
            .map(|[a, b, c, d]| (a, b, c, d))
            .collect();
        let constructor_payload_len =
            constants.len() * WORD_BYTES + (fixed_comms.len() + permutation_comms.len()) * G1_BYTES;
        let constructor_memory =
            VkConstructorMemoryLayout::new(constructor_payload_len + VK_RUNTIME_PREFIX_LEN);
        constructor_memory
            .validate()
            .unwrap_or_else(|err| panic!("invalid VK constructor memory layout: {err}"));
        Halo2VerifyingKey {
            constructor_payload_mptr: constructor_memory.payload_mptr,
            constants,
            fixed_comms,
            permutation_comms,
            quotient_const_offset_words: None,
            quotient_const_words: 0,
            quotient_program_offset_words: None,
            quotient_program_words: 0,
        }
    }

    /// Generate the final VK payload, including compact quotient VM data.
    ///
    /// The quotient program depends on memory addresses, and memory addresses
    /// depend on the final VK length. This method reserves zero-filled quotient
    /// sections first, rebuilds against the final layout, and then fills the
    /// sections. Assertions catch any non-convergent program size change.
    fn generate_vk(&self) -> Halo2VerifyingKey {
        let proof_cptr = Ptr::calldata(layout::abi::VERIFY_PROOF_PROOF_CPTR);
        let mut vk = self.generate_base_vk();
        if quotient_inline_cse_enabled() || quotient_structured_loops_enabled() {
            vk.validate_payload_layout()
                .unwrap_or_else(|err| panic!("invalid generated VK payload layout: {err}"));
            return vk;
        }

        let header_words = vk.constants.len();
        let mut quotient_const_words = 0usize;
        let mut quotient_program_words = 0usize;
        let mut quotient_program_build = None;

        for _ in 0..8 {
            vk.constants.truncate(header_words);
            vk.constants
                .extend((0..quotient_const_words).map(|_| ("quotient_const", U256::ZERO)));
            vk.constants
                .extend((0..quotient_program_words).map(|_| ("quotient_program", U256::ZERO)));
            vk.quotient_const_offset_words = None;
            vk.quotient_const_words = 0;
            vk.quotient_program_offset_words = None;
            vk.quotient_program_words = 0;

            let (_, meta, data, _) = self.meta_data_for_stable_static_layout(&vk, proof_cptr);
            let (candidate, _) = self.compact_quotient_program_for(&meta, &data);
            let candidate_const_words = candidate.consts.len();
            let candidate_program_words =
                PackedProgramCodec::word_len_for_bytes(candidate.bytes.len());

            if candidate_const_words <= quotient_const_words
                && candidate_program_words <= quotient_program_words
            {
                quotient_program_build = Some(candidate);
                break;
            }

            quotient_const_words = quotient_const_words.max(candidate_const_words);
            quotient_program_words = quotient_program_words.max(candidate_program_words);
        }

        let quotient_program_build = quotient_program_build.unwrap_or_else(|| {
            panic!(
                "quotient VK payload reservation did not converge after 8 iterations: const_words={quotient_const_words}, program_words={quotient_program_words}"
            )
        });
        let payload_layout = VkPayloadLayout::for_vk(
            header_words,
            quotient_const_words,
            quotient_program_words,
            vk.fixed_comms.len(),
            vk.permutation_comms.len(),
        )
        .unwrap_or_else(|err| panic!("invalid VK payload layout reservation: {err}"));
        let quotient_const_offset_words = payload_layout
            .word_offset(PayloadSectionKind::QuotientConstants)
            .expect("quotient constants section");
        let quotient_program_offset_words = payload_layout
            .word_offset(PayloadSectionKind::QuotientProgram)
            .expect("quotient program section");
        assert_eq!(
            payload_layout
                .word_len(PayloadSectionKind::QuotientConstants)
                .expect("quotient constants section length"),
            quotient_const_words
        );
        assert_eq!(
            payload_layout
                .word_len(PayloadSectionKind::QuotientProgram)
                .expect("quotient program section length"),
            quotient_program_words
        );
        assert_eq!(
            payload_layout.total_bytes(),
            vk.len(),
            "typed VK payload layout must preserve the emitted byte length"
        );

        let quotient_program_chunks =
            PackedProgramCodec::encode_words(&quotient_program_build.bytes);
        assert!(
            quotient_program_build.consts.len() <= quotient_const_words,
            "quotient const table exceeded VK payload reservation"
        );
        assert!(
            quotient_program_chunks.len() <= quotient_program_words,
            "quotient program length exceeded VK payload reservation"
        );

        for (i, value) in quotient_program_build.consts.iter().copied().enumerate() {
            vk.constants[quotient_const_offset_words + i] = ("quotient_const", value);
        }
        for (i, value) in quotient_program_chunks.iter().copied().enumerate() {
            vk.constants[quotient_program_offset_words + i] = ("quotient_program", value);
        }

        vk.quotient_const_offset_words = Some(quotient_const_offset_words);
        vk.quotient_const_words = quotient_const_words;
        vk.quotient_program_offset_words = Some(quotient_program_offset_words);
        vk.quotient_program_words = quotient_program_words;
        vk.validate_payload_layout()
            .unwrap_or_else(|err| panic!("invalid generated VK payload layout: {err}"));
        vk
    }

    /// Build metadata, data handles, and memory layout for a candidate VK base.
    fn meta_data_for_vk(
        &self,
        vk: &Halo2VerifyingKey,
        vk_mptr: Ptr,
        proof_cptr: Ptr,
    ) -> (ConstraintSystemMeta, Data, VerifierMemoryLayout) {
        // ------------------------------------------------------------------
        // Phase 3 / outer-fewer-point-sets two-pass `Data` construction.
        //
        // Pass 1: build `Data` against the *raw* meta (no dummy evals).
        //   This gives us the raw query list whose commitment identity
        //   structure feeds `compute_dummy_queries`.
        //
        // Pass 2: bump meta.num_evals by the dummy count (so the
        //   memory layout - REVERSED_EVALS_MPTR buffer + downstream
        //   comms_mptr_base - grows to fit the dummies), rebuild Data,
        //   and populate the dummy eval Words.
        //
        // When the `outer-fewer-point-sets` Cargo feature is OFF, the dummy
        // count is forced to zero; pass 2 collapses to "rebuild Data
        // against unchanged meta", and the result is byte-identical
        // to the pre-Phase-3 single-pass path.
        // ------------------------------------------------------------------
        let raw_memory = self.memory_layout_for(
            &self.meta,
            vk,
            vk_mptr,
            VerifierMemoryLayoutConfig::default(),
        );
        let raw_data = Data::new(&self.meta, vk, proof_cptr, &raw_memory);
        let mut meta = self.meta.clone();
        let n_dummy = if cfg!(feature = "outer-fewer-point-sets") {
            pcs::num_dummy_queries(&meta, &raw_data)
        } else {
            0
        };
        let main_evals = meta.num_evals;
        meta.set_num_dummy_evals(n_dummy);
        let memory =
            self.memory_layout_for(&meta, vk, vk_mptr, VerifierMemoryLayoutConfig::default());
        let mut data = Data::new(&meta, vk, proof_cptr, &memory);
        if n_dummy > 0 {
            data.set_dummy_eval_words(main_evals, n_dummy);
        }

        meta.set_num_point_sets(pcs::num_point_sets(&meta, &data));
        let memory =
            self.memory_layout_for(&meta, vk, vk_mptr, VerifierMemoryLayoutConfig::default());
        (meta, data, memory)
    }

    /// Find a VK memory base that is stable after proof-shape planning.
    ///
    /// Transcript/PCS low-memory requirements can grow when dummy query planning
    /// discovers extra eval scalars. Iterate until the chosen `VK_MPTR` matches
    /// the requirements computed from the resulting metadata.
    fn meta_data_for_stable_static_layout(
        &self,
        vk: &Halo2VerifyingKey,
        proof_cptr: Ptr,
    ) -> (Ptr, ConstraintSystemMeta, Data, VerifierMemoryLayout) {
        let mut vk_mptr = Ptr::memory(self.static_working_memory_size_for_meta(&self.meta));

        for _ in 0..3 {
            let (meta, data, memory) = self.meta_data_for_vk(vk, vk_mptr, proof_cptr);
            let planned_mptr = self.static_working_memory_size_for_meta(&meta);
            if planned_mptr == vk_mptr.value().as_usize() {
                return (vk_mptr, meta, data, memory);
            }
            vk_mptr = Ptr::memory(planned_mptr);
        }

        panic!("static verifier memory layout did not converge after proof-shape planning");
    }

    /// Build a verifier memory layout after filling derived config fields.
    fn memory_layout_for(
        &self,
        meta: &ConstraintSystemMeta,
        vk: &Halo2VerifyingKey,
        vk_mptr: Ptr,
        mut config: VerifierMemoryLayoutConfig,
    ) -> VerifierMemoryLayout {
        config.transcript_words =
            Self::transcript_buffer_layout_for_meta(meta, self.num_instances).words;
        config.num_instances = self.num_instances;
        VerifierMemoryLayout::new(meta, vk, vk_mptr, config)
    }

    /// Build the compact quotient VM artifact for a metadata/data snapshot.
    fn compact_quotient_program_for(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> (QuotientProgramBuild, Vec<usize>) {
        // Build the exact compact program carried by the VK. This helper is
        // also used during static-layout convergence, so its output must be
        // deterministic for a fixed VK base and proof shape.
        let plan = self.quotient_program_plan(meta, data);
        let sorted_simple = plan.sorted_simple.clone();
        let quotient_program_build =
            self.build_quotient_program_items(&plan.items, &plan.selector_fold);
        let _quotient_max_stack = quotient_program_build.max_stack;
        (quotient_program_build, sorted_simple)
    }

    /// Convert finalized bytecode usage into template switch-arm flags.
    fn quotient_opcode_usage(used_ops: &[u8]) -> QuotientVmOpcodeUsage {
        let has = |op| used_ops.contains(&op);
        QuotientVmOpcodeUsage {
            push_const: has(Q_OP_PUSH_CONST),
            push_mem_literal: has(Q_OP_PUSH_MEM_LITERAL),
            push_mem_token: has(Q_OP_PUSH_MEM_TOKEN),
            push_mem_token_offset: has(Q_OP_PUSH_MEM_TOKEN_OFFSET),
            push_mem_u16: has(Q_OP_PUSH_MEM_U16),
            add: has(Q_OP_ADD),
            mul: has(Q_OP_MUL),
            neg: has(Q_OP_NEG),
            push_const_u8: has(Q_OP_PUSH_CONST_U8),
            fold_main: has(Q_OP_FOLD_MAIN),
            fold_selector: has(Q_OP_FOLD_SELECTOR),
            add_const_u8: has(Q_OP_ADD_CONST_U8),
            mul_const_u8: has(Q_OP_MUL_CONST_U8),
            add_const: has(Q_OP_ADD_CONST),
            mul_const: has(Q_OP_MUL_CONST),
            add_mem_u16: has(Q_OP_ADD_MEM_U16),
            mul_mem_u16: has(Q_OP_MUL_MEM_U16),
            add_mul_mem_mem_const_u8: has(Q_OP_ADD_MUL_MEM_MEM_CONST_U8),
            add_mul_const_u8_mem_u16: has(Q_OP_ADD_MUL_CONST_U8_MEM_U16),
            add_mul_mem_mem: has(Q_OP_ADD_MUL_MEM_MEM),
            run_add_mul_mem_mem_const_u8: has(Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8),
            run_add_mul_const_u8_mem_u16: has(Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16),
            push_temp: has(Q_OP_PUSH_TEMP),
            store_temp: has(Q_OP_STORE_TEMP),
            native_permutation: has(Q_OP_NATIVE_PERMUTATION),
            native_lookup: has(Q_OP_NATIVE_LOOKUP),
            native_identity: has(Q_OP_NATIVE_IDENTITY),
            lin7: has(Q_OP_LIN7),
            bilin7_row: has(Q_OP_BILIN7_ROW),
            bilin7_pairwise: has(Q_OP_BILIN7_PAIRWISE),
            modarith7: has(Q_OP_MODARITH7),
            pow5: has(Q_OP_POW5),
        }
    }

    /// Convert finalized memory-token usage into template switch-arm flags.
    fn quotient_mem_usage(used_tokens: &[u8]) -> QuotientVmMemUsage {
        let has = |token| used_tokens.contains(&token);
        QuotientVmMemUsage {
            l0: has(Q_MEM_L0),
            l_last: has(Q_MEM_L_LAST),
            l_blind: has(Q_MEM_L_BLIND),
            beta: has(Q_MEM_BETA),
            gamma: has(Q_MEM_GAMMA),
            x: has(Q_MEM_X),
            theta: has(Q_MEM_THETA),
            trash_challenge: has(Q_MEM_TRASH_CHALLENGE),
            instance_eval: has(Q_MEM_INSTANCE_EVAL),
        }
    }

    /// Return stack/scratch words needed by interpreted VM and native callbacks.
    fn quotient_stack_words_for_build(
        build: &QuotientProgramBuild,
        native_callback_scratch_words: usize,
    ) -> usize {
        // `build.max_stack` only describes the interpreted operand stack. Some
        // native callbacks share `quotient_stack_mptr` as a scratch base, so
        // the registered memory region must cover both possible users.
        build.max_stack.max(native_callback_scratch_words)
    }

    /// Number of persistent VM temp words needed for state plus selector powers.
    fn quotient_state_words(selector_fold: &SelectorFoldPlan) -> usize {
        Self::QUOTIENT_FIXED_STATE_WORDS + Self::selector_power_words(selector_fold)
    }

    /// Number of `y^k` words needed by selector gap/tail folding.
    fn selector_power_words(selector_fold: &SelectorFoldPlan) -> usize {
        if selector_fold.max_power == 0 {
            0
        } else {
            selector_fold.max_power + 1
        }
    }

    /// Render-time selector tail updates, omitting zero tails.
    fn selector_tail_updates(selector_fold: &SelectorFoldPlan) -> Vec<QuotientSelectorTail> {
        selector_fold
            .tail_exponents
            .iter()
            .enumerate()
            .filter_map(|(selector_idx, tail)| {
                (*tail != 0).then_some(QuotientSelectorTail {
                    selector_offset: selector_idx * WORD_BYTES,
                    power_offset: tail * WORD_BYTES,
                })
            })
            .collect()
    }

    /// Build the codegen-time selector gap schedule over the full identity stream.
    fn selector_fold_plan(
        identities: &[QuotientIdentity],
        selector_count: usize,
    ) -> SelectorFoldPlan {
        let mut gaps_by_identity = vec![None; identities.len()];
        let mut previous = vec![None; selector_count];
        let mut tail_exponents = vec![0; selector_count];
        let mut max_power = 0usize;

        for identity in identities {
            if let QuotientTarget::Selector(selector_idx) = identity.target {
                let index = identity.meta.global_index;
                let gap = previous[selector_idx].map_or(0, |prev| index - prev);
                gaps_by_identity[index] = Some(gap);
                max_power = max_power.max(gap);
                previous[selector_idx] = Some(index);
            }
        }

        for (selector_idx, last) in previous.into_iter().enumerate() {
            if let Some(last_index) = last {
                let tail = identities.len() - 1 - last_index;
                tail_exponents[selector_idx] = tail;
                max_power = max_power.max(tail);
            }
        }

        SelectorFoldPlan {
            gaps_by_identity,
            tail_exponents,
            max_power,
        }
    }

    /// Choose inline, VM, and native-callback representation for identities.
    fn quotient_program_plan(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> QuotientProgramPlan {
        // Preserve the Rust identity order while choosing an execution form for
        // each identity:
        //   * a small gate prefix can stay inline,
        //   * ordinary identities become compact VM bytecode,
        //   * recognized expensive gates plus regular permutation/lookup
        //     families become native callback markers in the same stream.
        let parts = self.quotient_identity_parts(meta, data);
        let all_identities = parts.all_identities();
        let selector_fold = Self::selector_fold_plan(&all_identities, parts.sorted_simple.len());
        let inline_count = hybrid_quotient_inline_count(&parts.gates);
        let inline_identities = parts.gates[..inline_count].to_vec();
        let remaining_gates = &parts.gates[inline_count..];
        let native_gate_indices = Self::native_gate_indices(remaining_gates);
        let native_permutation =
            quotient_native_permutation_enabled() && meta.num_permutation_zs > 0;
        let native_lookup = quotient_native_lookup_enabled() && meta.num_lookups > 0;
        let structured_trash_tail = quotient_structured_tail_mode()
            == QuotientStructuredTailMode::Trash
            && meta.num_trashcans > 0;

        let mut items = Vec::with_capacity(
            remaining_gates.len()
                + parts.permutation.len()
                + parts.lookup.len()
                + parts.trash.len()
                + usize::from(native_permutation)
                + usize::from(native_lookup),
        );
        let mut native_identities = Vec::with_capacity(native_gate_indices.len());
        for (gate_idx, identity) in remaining_gates.iter().enumerate() {
            if native_gate_indices.contains(&gate_idx) {
                let native_idx = native_identities.len();
                native_identities.push(identity.clone());
                items.push(QuotientProgramItem::NativeIdentity(native_idx));
            } else {
                items.push(QuotientProgramItem::Identity(identity.clone()));
            }
        }

        if native_permutation {
            items.push(QuotientProgramItem::NativePermutation);
        } else {
            items.extend(
                parts
                    .permutation
                    .iter()
                    .cloned()
                    .map(QuotientProgramItem::Identity),
            );
        }
        if native_lookup {
            items.push(QuotientProgramItem::NativeLookup);
        } else {
            items.extend(
                parts
                    .lookup
                    .iter()
                    .cloned()
                    .map(QuotientProgramItem::Identity),
            );
        }
        if !structured_trash_tail {
            items.extend(
                parts
                    .trash
                    .iter()
                    .cloned()
                    .map(QuotientProgramItem::Identity),
            );
        }

        QuotientProgramPlan {
            inline_identities,
            items,
            native_identities,
            sorted_simple: parts.sorted_simple,
            has_native_permutation: native_permutation,
            has_native_lookup: native_lookup,
            selector_fold,
        }
    }

    /// Pick native gate callbacks by estimated gas saved under a byte budget.
    fn native_gate_indices(gates: &[QuotientIdentity]) -> HashSet<usize> {
        let max_count = quotient_native_gate_count(gates);
        if max_count == 0 {
            return HashSet::new();
        }

        let candidates = Self::native_gate_candidates(gates);
        let byte_budget = quotient_native_gate_byte_budget()
            .unwrap_or_else(|| Self::default_native_gate_byte_budget(&candidates, max_count));
        let selection = Self::select_native_gate_candidates(&candidates, max_count, byte_budget);

        if quotient_shape_profile_enabled() {
            eprintln!(
                "native gate knapsack: candidates={} max_count={} byte_budget={} selected={:?} estimated_gas_saved={} estimated_native_bytes={}",
                candidates.len(),
                max_count,
                byte_budget,
                selection.gate_indices,
                selection.gas_saved,
                selection.native_bytes,
            );
        }

        selection.gate_indices.into_iter().collect()
    }

    /// Build per-gate native-callback selection metrics.
    fn native_gate_candidates(gates: &[QuotientIdentity]) -> Vec<NativeGateCandidate> {
        gates
            .iter()
            .enumerate()
            .map(|(gate_idx, identity)| {
                let (vm_bytes, vm_gas) = Self::quotient_identity_program_metrics(identity);
                let native_block = Self::native_identity_estimate_block(identity);
                let native_bytes = Self::yul_block_source_bytes(&native_block);
                let native_gas = Self::estimate_native_yul_gas(&native_block);
                NativeGateCandidate {
                    gate_idx,
                    vm_bytes,
                    native_bytes,
                    gas_saved: vm_gas.saturating_sub(native_gas),
                }
            })
            .collect()
    }

    /// Preserve the previous top-N byte envelope as the default native budget.
    fn default_native_gate_byte_budget(
        candidates: &[NativeGateCandidate],
        max_count: usize,
    ) -> usize {
        let mut ranked = candidates
            .iter()
            .map(|candidate| {
                (
                    candidate.vm_bytes,
                    candidate.gate_idx,
                    candidate.native_bytes,
                )
            })
            .collect::<Vec<_>>();
        ranked.sort_by(|(lhs_bytes, lhs_idx, _), (rhs_bytes, rhs_idx, _)| {
            rhs_bytes.cmp(lhs_bytes).then_with(|| lhs_idx.cmp(rhs_idx))
        });
        ranked
            .into_iter()
            .take(max_count)
            .map(|(_, _, native_bytes)| native_bytes)
            .sum()
    }

    /// Solve a small 0/1 knapsack: maximize estimated gas saved under bytes.
    fn select_native_gate_candidates(
        candidates: &[NativeGateCandidate],
        max_count: usize,
        byte_budget: usize,
    ) -> NativeGateSelectionState {
        if max_count == 0 || byte_budget == 0 {
            return NativeGateSelectionState::default();
        }

        const BYTE_UNIT: usize = 32;
        let budget_units = byte_budget.div_ceil(BYTE_UNIT);
        let mut dp = vec![vec![None::<NativeGateSelectionState>; budget_units + 1]; max_count + 1];
        dp[0][0] = Some(NativeGateSelectionState::default());

        for candidate in candidates
            .iter()
            .filter(|candidate| candidate.gas_saved > 0 && candidate.native_bytes > 0)
        {
            let cost_units = candidate.native_bytes.div_ceil(BYTE_UNIT).max(1);
            if cost_units > budget_units {
                continue;
            }

            for count in (0..max_count).rev() {
                for used in (0..=budget_units - cost_units).rev() {
                    let Some(state) = dp[count][used].clone() else {
                        continue;
                    };
                    let mut next = state;
                    next.gas_saved += candidate.gas_saved;
                    next.native_bytes += candidate.native_bytes;
                    next.gate_indices.push(candidate.gate_idx);

                    let next_count = count + 1;
                    let next_used = used + cost_units;
                    if Self::native_gate_selection_better(&next, dp[next_count][next_used].as_ref())
                    {
                        dp[next_count][next_used] = Some(next);
                    }
                }
            }
        }

        let mut best = NativeGateSelectionState::default();
        for count_states in dp {
            for state in count_states.into_iter().flatten() {
                if Self::native_gate_selection_better(&state, Some(&best)) {
                    best = state;
                }
            }
        }
        best
    }

    /// Deterministic tie-breaker for native gate knapsack states.
    fn native_gate_selection_better(
        candidate: &NativeGateSelectionState,
        incumbent: Option<&NativeGateSelectionState>,
    ) -> bool {
        let Some(incumbent) = incumbent else {
            return true;
        };
        candidate
            .gas_saved
            .cmp(&incumbent.gas_saved)
            .then_with(|| incumbent.native_bytes.cmp(&candidate.native_bytes))
            .then_with(|| {
                incumbent
                    .gate_indices
                    .len()
                    .cmp(&candidate.gate_indices.len())
            })
            .then_with(|| incumbent.gate_indices.cmp(&candidate.gate_indices))
            == std::cmp::Ordering::Greater
    }

    /// Estimate the generated native callback block for one identity.
    fn native_identity_estimate_block(identity: &QuotientIdentity) -> Vec<String> {
        let state_slots = QuotientStateSlots {
            eval_numer_mptr: 0x2000,
            trace_id_mptr: 0x2020,
            selector_power_mptr: 0x2040,
        };
        let selector_gap = matches!(identity.target, QuotientTarget::Selector(_)).then_some(1);
        Self::direct_quotient_block(
            &identity.lines,
            &identity.var,
            identity.target,
            selector_gap,
            &[],
            0x1000,
            Some(state_slots),
            false,
        )
    }

    /// Source-byte proxy for the native callback's contribution to runtime size.
    fn yul_block_source_bytes(block: &[String]) -> usize {
        block.iter().map(|line| line.len() + 1).sum()
    }

    /// Relative gas proxy for a generated native Yul callback.
    fn estimate_native_yul_gas(block: &[String]) -> u64 {
        let raw = block
            .iter()
            .map(|line| {
                let mut gas = 4u64;
                gas += 8 * line.matches("mload(").count() as u64;
                gas += 10 * line.matches("mstore(").count() as u64;
                gas += 38 * line.matches("addmod(").count() as u64;
                gas += 42 * line.matches("mulmod(").count() as u64;
                gas += 18 * line.matches("add(").count() as u64;
                gas += 18 * line.matches("sub(").count() as u64;
                gas += 16 * line.matches("mul(").count() as u64;
                gas
            })
            .sum::<u64>();
        // This is a relative selector score, not an absolute EVM gas model:
        // straight-line native Yul avoids the compact VM's dispatch overhead.
        raw / 2
    }

    /// Estimate compact-VM byte and gas cost of one identity.
    fn quotient_identity_program_metrics(identity: &QuotientIdentity) -> (usize, u64) {
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(quotient_limb_vm_ops_enabled());
        let expr = Self::quotient_identity_expr(identity);
        let selector_gap = matches!(identity.target, QuotientTarget::Selector(_)).then_some(0);
        builder.identity_expr(&expr, identity.target, selector_gap, None);
        let gas = Self::estimate_quotient_vm_gas(&builder.bytes);
        (builder.bytes.len(), gas)
    }

    /// Relative gas proxy for the compact quotient VM interpreter.
    fn estimate_quotient_vm_gas(bytes: &[u8]) -> u64 {
        let mut gas = 0u64;
        let mut idx = 0usize;
        while idx < bytes.len() {
            let op = bytes[idx];
            gas += match op {
                Q_OP_PUSH_CONST => 54,
                Q_OP_PUSH_MEM_LITERAL => 56,
                Q_OP_PUSH_MEM_TOKEN => 60,
                Q_OP_PUSH_MEM_TOKEN_OFFSET => 66,
                Q_OP_PUSH_MEM_U16 => 48,
                Q_OP_ADD => 38,
                Q_OP_MUL => 42,
                Q_OP_NEG => 24,
                Q_OP_PUSH_CONST_U8 => 42,
                Q_OP_FOLD_MAIN => 70,
                Q_OP_FOLD_SELECTOR => 92,
                Q_OP_ADD_CONST_U8 | Q_OP_ADD_CONST => 46,
                Q_OP_MUL_CONST_U8 | Q_OP_MUL_CONST => 50,
                Q_OP_ADD_MEM_U16 => 48,
                Q_OP_MUL_MEM_U16 => 52,
                Q_OP_ADD_MUL_MEM_MEM_CONST_U8 => 78,
                Q_OP_ADD_MUL_CONST_U8_MEM_U16 => 66,
                Q_OP_ADD_MUL_MEM_MEM => 70,
                Q_OP_RUN_ADD_MUL_MEM_MEM_CONST_U8 => {
                    let count = read_u16(bytes, idx + 1) as u64;
                    32 + 58 * count
                }
                Q_OP_RUN_ADD_MUL_CONST_U8_MEM_U16 => {
                    let count = read_u16(bytes, idx + 1) as u64;
                    32 + 48 * count
                }
                Q_OP_PUSH_TEMP | Q_OP_STORE_TEMP => 42,
                Q_OP_NATIVE_PERMUTATION | Q_OP_NATIVE_LOOKUP => 0,
                Q_OP_NATIVE_IDENTITY => 0,
                Q_OP_LIN7 => 190,
                Q_OP_BILIN7_ROW => 260,
                Q_OP_BILIN7_PAIRWISE => 980,
                Q_OP_MODARITH7 => 90 + 9 * quotient_op_len(bytes, idx) as u64,
                Q_OP_POW5 => 58,
                _ => quotient_op_len(bytes, idx) as u64 * 12,
            };
            idx += quotient_op_len(bytes, idx);
        }
        gas
    }

    /// Compute the copied-memory frame required by the external evaluator.
    fn quotient_external_frame(
        vk_mptr: Ptr,
        vk_len: usize,
        meta: &ConstraintSystemMeta,
        memory: &VerifierMemoryLayout,
        simple_selector_count: usize,
    ) -> QuotientExternal {
        let frame_base = vk_mptr.value().as_usize();
        Self::quotient_external_frame_from_bounds(
            frame_base,
            vk_len,
            memory.reversed_evals_mptr.value().as_usize(),
            meta.num_evals,
            simple_selector_count,
        )
    }

    /// Compute an external quotient frame from already-known range bounds.
    pub(super) fn quotient_external_frame_from_bounds(
        frame_base: usize,
        vk_len: usize,
        evals_base: usize,
        num_evals: usize,
        simple_selector_count: usize,
    ) -> QuotientExternal {
        let vk_end = frame_base + vk_len;
        let evals_end = evals_base + num_evals * WORD_BYTES;
        let frame_end = vk_end.max(evals_end);
        QuotientExternal {
            frame_base,
            frame_len: frame_end - frame_base,
            output_len: 2 * WORD_BYTES + simple_selector_count * WORD_BYTES,
            magic: QUOTIENT_EXTERNAL_MAGIC,
        }
    }

    /// Split the quotient identity stream into gate/permutation/lookup/trash parts.
    ///
    /// Upstream reference: `plonk::partially_evaluate_identities` returns gate
    /// identities first, then permutation, lookup, and trash identities, with
    /// simple-selector gates tagged by their fixed-column index. This method
    /// preserves that order and converts selector columns into local bucket
    /// indices used by the generated linearization MSM.
    fn quotient_identity_parts(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
    ) -> QuotientIdentityParts {
        // This is the codegen-time split of Midfall's
        // `partially_evaluate_identities` comment: the Rust verifier returns
        // `(Option<selector_column>, evaluation)` for gates first, then
        // permutation, lookup, and trash identities. `Some(selector_column)`
        // means the identity is gated by a simple multiplicative selector and
        // must feed a selector bucket in `compute_linearization_commitment`;
        // `None` means it is fully evaluated and contributes to the negated
        // expected scalar.
        let evaluator = Evaluator::new(self.vk.cs(), meta, data);
        let gate_items = evaluator.gate_computations_tagged();
        let gate_exprs = self
            .vk
            .cs()
            .gates()
            .iter()
            .flat_map(|gate| gate.polynomials().iter())
            .map(|poly| Self::quotient_expr_from_plonk_expr(meta, data, poly))
            .collect::<Vec<_>>();
        assert_eq!(
            gate_items.len(),
            gate_exprs.len(),
            "gate Yul expressions and typed expressions must stay aligned"
        );
        let perm_items = evaluator.permutation_computations();
        let lookup_items = evaluator.lookup_computations();
        let trash_items = evaluator.trashcan_computations();

        let mut sorted_simple: Vec<usize> = meta.simple_selector_cols.iter().copied().collect();
        sorted_simple.sort_unstable();

        let mut global_index = 0usize;
        let mut gates = Vec::with_capacity(gate_items.len());
        for (item, expr) in gate_items.into_iter().zip(gate_exprs) {
            let target = match item.simple_selector_index {
                Some(col) => {
                    let idx = sorted_simple
                        .iter()
                        .position(|simple| *simple == col)
                        .expect("selector column present");
                    QuotientTarget::Selector(idx)
                }
                None => QuotientTarget::Main,
            };
            gates.push(QuotientIdentity {
                meta: QuotientIdentityMetadata {
                    global_index,
                    source: QuotientIdentitySource::Gate {
                        gate_index: item.gate_index,
                        gate_name: item.gate_name,
                        constraint_index: item.constraint_index,
                        constraint_name: item.constraint_name,
                        polynomial_index: item.polynomial_index,
                    },
                },
                lines: item.lines,
                var: item.var,
                target,
                expr: Some(expr),
            });
            global_index += 1;
        }
        let mut permutation = Vec::with_capacity(perm_items.len());
        for (identity_index, (lines, var)) in perm_items.into_iter().enumerate() {
            permutation.push(QuotientIdentity {
                meta: QuotientIdentityMetadata {
                    global_index,
                    source: QuotientIdentitySource::Permutation { identity_index },
                },
                lines,
                var,
                target: QuotientTarget::Main,
                expr: None,
            });
            global_index += 1;
        }
        let mut lookup = Vec::with_capacity(lookup_items.len());
        for (identity_index, (lines, var)) in lookup_items.into_iter().enumerate() {
            let (lookup_index, _) = meta
                .protocol
                .lookup_identity_source(identity_index)
                .expect("lookup identity index covered by protocol lookup chunks");
            let lookup_name = format!("lookup_{lookup_index}");
            lookup.push(QuotientIdentity {
                meta: QuotientIdentityMetadata {
                    global_index,
                    source: QuotientIdentitySource::Lookup {
                        identity_index,
                        lookup_index,
                        lookup_name,
                    },
                },
                lines,
                var,
                target: QuotientTarget::Main,
                expr: None,
            });
            global_index += 1;
        }
        let mut trash = Vec::with_capacity(trash_items.len());
        for (trash_index, (lines, var)) in trash_items.into_iter().enumerate() {
            let trash_name = self.trash_manifest_name(trash_index);
            trash.push(QuotientIdentity {
                meta: QuotientIdentityMetadata {
                    global_index,
                    source: QuotientIdentitySource::Trash {
                        trash_index,
                        trash_name,
                    },
                },
                lines,
                var,
                target: QuotientTarget::Main,
                expr: None,
            });
            global_index += 1;
        }

        assert_eq!(
            gates.len(),
            meta.protocol.quotient.gates,
            "gate identity count must match protocol plan"
        );
        assert_eq!(
            permutation.len(),
            meta.protocol.quotient.permutation,
            "permutation identity count must match protocol plan"
        );
        assert_eq!(
            lookup.len(),
            meta.protocol.quotient.lookup,
            "lookup identity count must match protocol plan"
        );
        assert_eq!(
            trash.len(),
            meta.protocol.quotient.trash,
            "trash identity count must match protocol plan"
        );

        QuotientIdentityParts {
            gates,
            permutation,
            lookup,
            trash,
            sorted_simple,
        }
    }

    /// Return the typed quotient expression, parsing legacy Yul if necessary.
    fn quotient_identity_expr(identity: &QuotientIdentity) -> QuotientExpr {
        if let Some(expr) = &identity.expr {
            return expr.clone();
        }
        Self::quotient_identity_yul_expr(identity)
    }

    /// Parse an evaluator-emitted Yul identity into the quotient AST.
    fn quotient_identity_yul_expr(identity: &QuotientIdentity) -> QuotientExpr {
        let mut parser = QuotientProgramBuilder::default();
        for line in &identity.lines {
            parser.assignment(line);
        }
        parser.parse_expr(&identity.var)
    }

    /// Lower a Halo2 expression into the quotient AST using generated data.
    fn quotient_expr_from_plonk_expr(
        meta: &ConstraintSystemMeta,
        data: &Data,
        expression: &Expression<Fq>,
    ) -> QuotientExpr {
        quotient_expr_from_expression(&DataQuotientExpressionEnv { meta, data }, expression)
    }

    /// Emit direct quotient computations with memory-backed CSE.
    ///
    /// This path is a measurement/debug representation of the same identity
    /// stream. It keeps the Rust linearization invariant from
    /// `compute_linearization_commitment`: selector identities go to selector
    /// buckets, fully evaluated identities go to the numerator scalar.
    fn inline_cse_quotient_computations(
        identities: &[QuotientIdentity],
        sorted_simple: &[usize],
        cse_mptr: usize,
        helpers: bool,
        trace: bool,
    ) -> Vec<Vec<String>> {
        let sel_var = |idx: usize| format!("sel_acc_{}", sorted_simple[idx]);
        let exprs = identities
            .iter()
            .map(Self::quotient_identity_yul_expr)
            .collect::<Vec<_>>();
        let plan = QuotientInlineCsePlan::new(&exprs);
        let eval_scratch_slot = cse_mptr + plan.slots.len() * 0x20;
        let mut emitter = QuotientInlineCseEmitter::new(&plan, cse_mptr, helpers);
        let mut computations = Vec::new();

        let mut init_lines = Vec::new();
        init_lines.push("let quotient_eval_numer := 0".to_string());
        for idx in 0..sorted_simple.len() {
            init_lines.push(format!("let {} := 0", sel_var(idx)));
        }
        computations.push(init_lines);

        for (identity, expr) in identities.iter().zip(exprs.iter()) {
            let mut block = Vec::with_capacity(identity.lines.len() + 8 + sorted_simple.len());
            block.push("{".to_string());
            let value = emitter.emit_identity(expr, &mut block);
            block.push(format!("mstore({eval_scratch_slot:#x}, {value})"));
            block.push("}".to_string());
            if trace {
                block.push(format!(
                    "trace_u256(q_trace_id, mload({eval_scratch_slot:#x}))"
                ));
                block.push("q_trace_id := add(q_trace_id, 1)".to_string());
            }
            block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
            for idx in 0..sorted_simple.len() {
                block.push(format!(
                    "{name} := mulmod({name}, y, r)",
                    name = sel_var(idx)
                ));
            }
            let target = match identity.target {
                QuotientTarget::Selector(idx) => sel_var(idx),
                QuotientTarget::Main => "quotient_eval_numer".to_string(),
            };
            block.push(format!(
                "{target} := addmod({target}, mload({eval_scratch_slot:#x}), r)"
            ));
            computations.push(block);
        }

        if !sorted_simple.is_empty() {
            let mut tail = Vec::new();
            for i in 0..sorted_simple.len() {
                tail.push(format!(
                    "mstore(add(SELECTOR_ACC_MPTR, {:#x}), {})",
                    i * 0x20,
                    sel_var(i)
                ));
            }
            computations.push(tail);
        }

        computations
    }

    /// Emit one direct/native quotient identity block and its y-fold side effects.
    fn direct_quotient_block(
        lines: &[String],
        var: &str,
        target: QuotientTarget,
        selector_gap: Option<usize>,
        sorted_simple: &[usize],
        eval_scratch_slot: usize,
        state_slots: Option<QuotientStateSlots>,
        trace: bool,
    ) -> Vec<String> {
        let mut block = Vec::with_capacity(lines.len() + 6);
        block.push("{".to_string());
        let lines = Self::specialize_limb7_chains(lines);
        for line in &lines {
            block.push(line.clone());
        }
        block.push(format!("mstore({eval_scratch_slot:#x}, {var})"));
        block.push("}".to_string());
        Self::push_quotient_trace(
            &mut block,
            state_slots,
            format!("mload({eval_scratch_slot:#x})"),
            trace,
        );
        Self::push_structured_fold_advance(
            &mut block,
            1,
            sorted_simple,
            "q_direct_fold_i",
            state_slots,
        );
        match target {
            QuotientTarget::Main => {
                Self::push_quotient_eval_numer_add(
                    &mut block,
                    state_slots,
                    format!("mload({eval_scratch_slot:#x})"),
                );
            }
            QuotientTarget::Selector(idx) => {
                let offset = idx * 0x20;
                if let Some(slots) = state_slots {
                    let gap = selector_gap.expect("selector gap for compact direct quotient block");
                    block.push("{".to_string());
                    block.push(format!(
                        "let q_selector_ptr := add(SELECTOR_ACC_MPTR, {offset:#x})"
                    ));
                    block.push("let q_selector_acc := mload(q_selector_ptr)".to_string());
                    if gap != 0 {
                        block.push(format!(
                            "q_selector_acc := mulmod(q_selector_acc, mload(add({:#x}, {:#x})), r)",
                            slots.selector_power_mptr,
                            gap * WORD_BYTES
                        ));
                    }
                    block.push(format!(
                        "mstore(q_selector_ptr, addmod(q_selector_acc, mload({eval_scratch_slot:#x}), r))"
                    ));
                    block.push("}".to_string());
                } else {
                    block.push(format!(
                        "mstore(add(SELECTOR_ACC_MPTR, {offset:#x}), addmod(mload(add(SELECTOR_ACC_MPTR, {offset:#x})), mulmod(mload({eval_scratch_slot:#x}), q_sel_inv_scale, r), r))"
                    ));
                }
            }
        }
        block
    }

    /// Append trace emission for a quotient identity value.
    fn push_quotient_trace(
        block: &mut Vec<String>,
        state_slots: Option<QuotientStateSlots>,
        value: impl AsRef<str>,
        trace: bool,
    ) {
        if !trace {
            return;
        }

        let value = value.as_ref();
        if let Some(slots) = state_slots {
            block.push(format!(
                "trace_u256(mload({:#x}), {value})",
                slots.trace_id_mptr
            ));
            block.push(format!(
                "mstore({:#x}, add(mload({:#x}), 1))",
                slots.trace_id_mptr, slots.trace_id_mptr
            ));
        } else {
            block.push(format!("trace_u256(q_trace_id, {value})"));
            block.push("q_trace_id := add(q_trace_id, 1)".to_string());
        }
    }

    /// Add an identity value into the current numerator accumulator.
    fn push_quotient_eval_numer_add(
        block: &mut Vec<String>,
        state_slots: Option<QuotientStateSlots>,
        value: impl AsRef<str>,
    ) {
        let value = value.as_ref();
        if let Some(slots) = state_slots {
            block.push(format!(
                "mstore({:#x}, addmod(mload({:#x}), {value}, r))",
                slots.eval_numer_mptr, slots.eval_numer_mptr
            ));
        } else {
            block.push(format!(
                "quotient_eval_numer := addmod(quotient_eval_numer, {value}, r)"
            ));
        }
    }

    /// Advance the global y-fold state by `count` identity positions.
    ///
    /// Compact VM mode advances only the main accumulator here: selector
    /// buckets use codegen-time gap updates at selector identity positions.
    /// Legacy/direct modes keep the older inverse-scale selector fold.
    fn push_structured_fold_advance(
        block: &mut Vec<String>,
        count: usize,
        sorted_simple: &[usize],
        loop_var: &str,
        state_slots: Option<QuotientStateSlots>,
    ) {
        let push_one = |block: &mut Vec<String>| {
            if let Some(slots) = state_slots {
                block.push(format!(
                    "mstore({:#x}, mulmod(mload({:#x}), y, r))",
                    slots.eval_numer_mptr, slots.eval_numer_mptr
                ));
            } else {
                block.push("quotient_eval_numer := mulmod(quotient_eval_numer, y, r)".to_string());
                if !sorted_simple.is_empty() {
                    block.push("q_sel_scale := mulmod(q_sel_scale, y, r)".to_string());
                    block
                        .push("q_sel_inv_scale := mulmod(q_sel_inv_scale, q_y_inv, r)".to_string());
                }
            }
        };

        if count == 1 {
            push_one(block);
            return;
        }

        block.push(format!(
            "for {{ let {loop_var} := 0 }} lt({loop_var}, {count}) {{ {loop_var} := add({loop_var}, 1) }} {{"
        ));
        push_one(block);
        block.push("}".to_string());
    }

    /// Compact runs of adjacent `mstore(dst+i, mload(src+i*stride))` lines.
    ///
    /// Native callbacks often stage contiguous eval tables. This helper emits a
    /// small copy loop when the staged source and destination offsets form a
    /// regular run, otherwise it leaves the original store shape intact.
    fn push_mstore_mload_literal_runs(
        block: &mut Vec<String>,
        dst: &str,
        entries: &[(usize, String)],
        loop_prefix: &str,
    ) {
        let mut idx = 0usize;
        while idx < entries.len() {
            let (dst_base, expr) = &entries[idx];
            let Some(src_base) = yul_mload_literal_expr(expr) else {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            };
            let Some((next_dst, next_expr)) = entries.get(idx + 1) else {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            };
            if *next_dst != *dst_base + 0x20 {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            }
            let Some(next_src) = yul_mload_literal_expr(next_expr) else {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            };
            let Some(src_stride) = next_src.checked_sub(src_base) else {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            };
            if src_stride == 0 {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            }

            let mut count = 2usize;
            while let Some((candidate_dst, candidate_expr)) = entries.get(idx + count) {
                let Some(candidate_src) = yul_mload_literal_expr(candidate_expr) else {
                    break;
                };
                if *candidate_dst != *dst_base + count * 0x20
                    || candidate_src != src_base + count * src_stride
                {
                    break;
                }
                count += 1;
            }

            if count < 3 {
                block.push(format!("mstore(add({dst}, {dst_base:#x}), {expr})"));
                idx += 1;
                continue;
            }

            block.push("{".to_string());
            block.push(format!(
                "for {{ let {loop_prefix}_i := 0 }} lt({loop_prefix}_i, {count}) {{ {loop_prefix}_i := add({loop_prefix}_i, 1) }} {{"
            ));
            block.push(format!(
                "let {loop_prefix}_dst_off := shl(5, {loop_prefix}_i)"
            ));
            if src_stride == 0x20 {
                block.push(format!(
                    "let {loop_prefix}_src_off := {loop_prefix}_dst_off"
                ));
            } else {
                block.push(format!(
                    "let {loop_prefix}_src_off := mul({loop_prefix}_i, {src_stride:#x})"
                ));
            }
            block.push(format!(
                "mstore(add(add({dst}, {dst_base:#x}), {loop_prefix}_dst_off), mload(add({src_base:#x}, {loop_prefix}_src_off)))"
            ));
            block.push("}".to_string());
            block.push("}".to_string());
            idx += count;
        }
    }

    /// Return whether two Yul operands match a pair in either order.
    fn yul_pair_matches(lhs: &str, rhs: &str, a: &str, b: &str) -> bool {
        (lhs == a && rhs == b) || (lhs == b && rhs == a)
    }

    /// Recognize `a_i + f_i - next_i` selector-gate identities.
    ///
    /// Consecutive recognized identities become a structured loop in
    /// `selector_linear_next_loop_block`, reducing the direct/native gate prefix
    /// without changing the identity order.
    fn parse_selector_linear_next_identity(
        lines: &[String],
        final_var: &str,
    ) -> Option<(usize, usize, usize)> {
        if lines.len() != 8 {
            return None;
        }

        let (one_var, one) = yul_let_assignment(&lines[0])?;
        if parse_u256(one.trim()) != U256::from(1u8) {
            return None;
        }

        let (a_var, a_addr) = yul_mload_literal_assignment(&lines[1])?;
        let (f_var, f_addr) = yul_mload_literal_assignment(&lines[2])?;
        let (sum_var, lhs, rhs) = yul_addmod_assignment(&lines[3])?;
        if !Self::yul_pair_matches(&lhs, &rhs, &a_var, &f_var) {
            return None;
        }

        let (next_var, next_addr) = yul_mload_literal_assignment(&lines[4])?;
        let (neg_var, neg_arg) = yul_sub_r_assignment(&lines[5])?;
        if neg_arg != next_var {
            return None;
        }

        let (eval_var, lhs, rhs) = yul_addmod_assignment(&lines[6])?;
        if !Self::yul_pair_matches(&lhs, &rhs, &sum_var, &neg_var) {
            return None;
        }

        let (scaled_var, lhs, rhs) = yul_mulmod_assignment(&lines[7])?;
        if scaled_var != final_var || !Self::yul_pair_matches(&lhs, &rhs, &one_var, &eval_var) {
            return None;
        }

        Some((a_addr, f_addr, next_addr))
    }

    /// Emit a loop for a run of adjacent selector linear-next identities.
    pub(super) fn selector_linear_next_loop_block(
        run: &[(Vec<String>, String)],
    ) -> Option<(usize, Vec<String>)> {
        let (a_base, f_base, next_base) =
            Self::parse_selector_linear_next_identity(&run.first()?.0, &run.first()?.1)?;
        let mut count = 1usize;
        while let Some((lines, var)) = run.get(count) {
            let Some((a_addr, f_addr, next_addr)) =
                Self::parse_selector_linear_next_identity(lines, var)
            else {
                break;
            };
            let off = count * 0x20;
            if a_addr != a_base + off || f_addr != f_base + off || next_addr != next_base + off {
                break;
            }
            count += 1;
        }

        if count < 3 {
            return None;
        }

        let mut block = Vec::with_capacity(10);
        block.push("{".to_string());
        block.push(format!(
            "for {{ let q_gate_lin_i := 0 }} lt(q_gate_lin_i, {count}) {{ q_gate_lin_i := add(q_gate_lin_i, 1) }} {{"
        ));
        block.push("let q_gate_lin_off := shl(5, q_gate_lin_i)".to_string());
        block.push(format!(
            "let q_gate_lin_a := mload(add({a_base:#x}, q_gate_lin_off))"
        ));
        block.push(format!(
            "let q_gate_lin_f := mload(add({f_base:#x}, q_gate_lin_off))"
        ));
        block.push(format!(
            "let q_gate_lin_next := mload(add({next_base:#x}, q_gate_lin_off))"
        ));
        block.push(
            "let q_gate_lin_eval := addmod(addmod(q_gate_lin_a, q_gate_lin_f, r), sub(r, q_gate_lin_next), r)"
                .to_string(),
        );
        block
            .push("q_gate_run := addmod(mulmod(q_gate_run, y, r), q_gate_lin_eval, r)".to_string());
        block.push("}".to_string());
        block.push("}".to_string());
        Some((count, block))
    }

    /// Emit one identity inside a selector run accumulator.
    fn push_selector_run_identity(
        block: &mut Vec<String>,
        lines: &[String],
        var: &str,
        eval_scratch_slot: usize,
    ) {
        block.push("{".to_string());
        let lines = Self::specialize_limb7_chains(lines);
        for line in &lines {
            block.push(line.clone());
        }
        block.push(format!("mstore({eval_scratch_slot:#x}, {var})"));
        block.push("}".to_string());
        block.push(format!(
            "q_gate_run := addmod(mulmod(q_gate_run, y, r), mload({eval_scratch_slot:#x}), r)"
        ));
    }

    /// Emit a grouped selector run and write its inverse-scaled selector bucket.
    fn selector_run_quotient_block(
        run: &[(Vec<String>, String)],
        selector_idx: usize,
        sorted_simple: &[usize],
        eval_scratch_slot: usize,
        state_slots: Option<QuotientStateSlots>,
    ) -> Vec<String> {
        assert!(
            state_slots.is_none(),
            "selector-run grouping is only used by the legacy inverse selector fold"
        );
        let capacity = run.iter().map(|(lines, _)| lines.len() + 5).sum::<usize>() + 10;
        let mut block = Vec::with_capacity(capacity);
        let offset = selector_idx * 0x20;

        block.push("{".to_string());
        block.push("let q_gate_run := 0".to_string());
        let mut idx = 0usize;
        while idx < run.len() {
            if let Some((consumed, mut loop_block)) =
                Self::selector_linear_next_loop_block(&run[idx..])
            {
                block.append(&mut loop_block);
                idx += consumed;
                continue;
            }
            let (lines, var) = &run[idx];
            Self::push_selector_run_identity(&mut block, lines, var, eval_scratch_slot);
            idx += 1;
        }
        Self::push_structured_fold_advance(
            &mut block,
            run.len(),
            sorted_simple,
            "q_gate_run_i",
            state_slots,
        );
        block.push(format!(
            "mstore(add(SELECTOR_ACC_MPTR, {offset:#x}), addmod(mload(add(SELECTOR_ACC_MPTR, {offset:#x})), mulmod(q_gate_run, q_sel_inv_scale, r), r))"
        ));
        block.push("}".to_string());
        block
    }

    /// Flush pending selector identities into either direct or grouped form.
    fn flush_structured_selector_run(
        computations: &mut Vec<Vec<String>>,
        pending_selector: &mut Option<usize>,
        pending_run: &mut Vec<(Vec<String>, String)>,
        sorted_simple: &[usize],
        eval_scratch_slot: usize,
        state_slots: Option<QuotientStateSlots>,
        trace: bool,
    ) {
        let Some(selector_idx) = pending_selector.take() else {
            return;
        };
        let run = std::mem::take(pending_run);
        if trace {
            for (lines, var) in run {
                computations.push(Self::direct_quotient_block(
                    &lines,
                    &var,
                    QuotientTarget::Selector(selector_idx),
                    None,
                    sorted_simple,
                    eval_scratch_slot,
                    state_slots,
                    trace,
                ));
            }
        } else if run.len() == 1 {
            let (lines, var) = run.into_iter().next().expect("selector run item");
            computations.push(Self::direct_quotient_block(
                &lines,
                &var,
                QuotientTarget::Selector(selector_idx),
                None,
                sorted_simple,
                eval_scratch_slot,
                state_slots,
                trace,
            ));
        } else if !run.is_empty() {
            computations.push(Self::selector_run_quotient_block(
                &run,
                selector_idx,
                sorted_simple,
                eval_scratch_slot,
                state_slots,
            ));
        }
    }

    /// Replace recognized seven-limb linear chains with helper calls.
    ///
    /// This operates on legacy/direct Yul text, not on the compact VM AST. The
    /// VM has its own structural limb opcodes; this helper keeps native Yul
    /// callbacks compact for the same foreign-field shapes.
    pub(super) fn specialize_limb7_chains(lines: &[String]) -> Vec<String> {
        let mut out = Vec::with_capacity(lines.len());
        let mut const_vars = HashMap::new();
        let mut idx = 0usize;

        while idx < lines.len() {
            if let Some((consumed, replacement, updated_consts)) =
                Self::try_limb7_chain(&lines[idx..], &const_vars, &LIMB7_YUL_COEFFS, "q_limb7")
                    .or_else(|| {
                        Self::try_limb7_chain(
                            &lines[idx..],
                            &const_vars,
                            &WIDE_LIMB7_YUL_COEFFS,
                            "q_limb7_wide",
                        )
                    })
            {
                const_vars = updated_consts;
                out.extend(replacement);
                idx += consumed;
                continue;
            }

            Self::record_yul_const_assignment(&lines[idx], &mut const_vars);
            out.push(lines[idx].clone());
            idx += 1;
        }

        out
    }

    /// Try to recognize one helper-compatible seven-limb add/mul chain.
    fn try_limb7_chain(
        lines: &[String],
        const_vars: &HashMap<String, String>,
        coeffs: &[&str; 6],
        helper_name: &str,
    ) -> Option<(usize, Vec<String>, HashMap<String, String>)> {
        let mut idx = 0usize;
        let mut keep = Vec::new();
        let mut args = Vec::with_capacity(7);
        let mut previous_acc: Option<String> = None;
        let mut local_consts = const_vars.clone();

        for (step, coeff) in coeffs.iter().enumerate() {
            let mut skipped = 0usize;
            let (mul_dst, mul_arg) = loop {
                if idx >= lines.len() || skipped > 4 {
                    return None;
                }

                if let Some((dst, arg)) =
                    Self::parse_limb7_mul_assignment(&lines[idx], coeff, &local_consts)
                {
                    break (dst, arg);
                }

                if yul_let_assignment(&lines[idx]).is_some() {
                    Self::record_yul_const_assignment(&lines[idx], &mut local_consts);
                    keep.push(lines[idx].clone());
                    idx += 1;
                    skipped += 1;
                } else {
                    return None;
                }
            };

            let (add_dst, lhs, rhs) = yul_addmod_assignment(lines.get(idx + 1)?)?;
            let addend = if lhs == mul_dst {
                rhs
            } else if rhs == mul_dst {
                lhs
            } else {
                return None;
            };

            if step == 0 {
                args.push(addend);
            } else if Some(addend.as_str()) != previous_acc.as_deref() {
                return None;
            }
            args.push(mul_arg);
            previous_acc = Some(add_dst);
            idx += 2;
        }

        let final_acc = previous_acc?;
        keep.push(format!(
            "let {final_acc} := {helper_name}({})",
            args.join(", ")
        ));
        Some((idx, keep, local_consts))
    }

    /// Parse one `mulmod(coeff, limb, r)` line in a limb7 chain.
    fn parse_limb7_mul_assignment(
        line: &str,
        expected_coeff: &str,
        const_vars: &HashMap<String, String>,
    ) -> Option<(String, String)> {
        let (dst, lhs, rhs) = yul_mulmod_assignment(line)?;
        if Self::yul_coeff_matches(&lhs, expected_coeff, const_vars) {
            Some((dst, rhs))
        } else if Self::yul_coeff_matches(&rhs, expected_coeff, const_vars) {
            Some((dst, lhs))
        } else {
            None
        }
    }

    /// Return whether a literal or constant variable equals `expected_coeff`.
    fn yul_coeff_matches(
        value: &str,
        expected_coeff: &str,
        const_vars: &HashMap<String, String>,
    ) -> bool {
        yul_const_value(value, const_vars).as_deref() == Some(expected_coeff)
    }

    /// Record `let name := const` bindings for later limb-chain matching.
    fn record_yul_const_assignment(line: &str, const_vars: &mut HashMap<String, String>) {
        let Some((dst, rhs)) = yul_let_assignment(line) else {
            return;
        };
        let Some(value) = yul_const_value(&rhs, const_vars) else {
            return;
        };
        const_vars.insert(dst, value);
    }

    /// Trace, advance, and accumulate one main quotient identity value.
    fn push_structured_main_fold(
        block: &mut Vec<String>,
        value: impl AsRef<str>,
        sorted_simple: &[usize],
        state_slots: Option<QuotientStateSlots>,
        trace: bool,
    ) {
        Self::push_quotient_trace(block, state_slots, value.as_ref(), trace);
        Self::push_structured_fold_advance(block, 1, sorted_simple, "q_main_fold_i", state_slots);
        Self::push_quotient_eval_numer_add(block, state_slots, value.as_ref());
    }

    /// Scratch table width used by the native permutation callback.
    fn structured_permutation_scratch_words(meta: &ConstraintSystemMeta) -> usize {
        if meta.num_permutation_zs == 0 {
            return 0;
        }

        let num_cols = meta.permutation_columns.len();
        let num_sets = meta.num_permutation_zs;
        // Native permutation code materializes the terms for every permutation
        // set into a contiguous scratch table rooted at the callback scratch
        // pointer. This is separate from VM operand-stack depth even when both
        // regions currently use `quotient_stack_mptr` as their base.
        // permutation values, permutation sigma values, z_cur, z_next,
        // z_last for every non-final set, and one spill slot for the
        // running delta base used by the native permutation callback.
        (2 * num_cols) + (2 * num_sets) + num_sets.saturating_sub(1) + 1
    }

    /// Maximum parallel input width across LogUp lookup chunks.
    fn structured_lookup_max_parallel(&self, meta: &ConstraintSystemMeta) -> usize {
        if meta.num_lookups == 0 {
            return 0;
        }

        let mut max_parallel = 1usize;
        for lookup in self.vk.cs().lookups() {
            let chunked = lookup.chunk_by_degree(self.vk.cs().degree());
            for input_chunk in chunked.input_expression_chunks() {
                max_parallel = max_parallel.max(input_chunk.len());
            }
        }
        max_parallel
    }

    /// Scratch table width used by the native lookup callback.
    fn structured_lookup_scratch_words(&self, meta: &ConstraintSystemMeta) -> usize {
        // Native lookup stages f+beta values plus prefix and suffix products.
        self.structured_lookup_max_parallel(meta) * 3
    }

    /// Largest scratch table needed by any enabled native VM callback.
    fn native_callback_scratch_words(
        &self,
        meta: &ConstraintSystemMeta,
        plan: &QuotientProgramPlan,
    ) -> usize {
        let permutation_words = plan
            .has_native_permutation
            .then(|| Self::structured_permutation_scratch_words(meta))
            .unwrap_or(0);
        let lookup_words = plan
            .has_native_lookup
            .then(|| self.structured_lookup_scratch_words(meta))
            .unwrap_or(0);
        permutation_words.max(lookup_words)
    }

    /// Emit a native structured loop for the full permutation identity block.
    ///
    /// The formula follows the upstream permutation verifier/evaluator:
    /// first-set boundary, last-set booleanity, set-to-set continuity, and
    /// active-row product equality for each chunk.
    fn structured_permutation_loop_block(
        meta: &ConstraintSystemMeta,
        data: &Data,
        evaluator: &Evaluator<'_>,
        sorted_simple: &[usize],
        scratch_mptr: usize,
        state_slots: Option<QuotientStateSlots>,
        trace: bool,
    ) -> Option<Vec<String>> {
        if meta.num_permutation_zs == 0 {
            return None;
        }

        let num_cols = meta.permutation_columns.len();
        let num_sets = meta.num_permutation_zs;
        let chunk_len = meta.permutation_chunk_len;
        let vals_mptr = scratch_mptr;
        let sigmas_mptr = vals_mptr + num_cols * 0x20;
        let z_cur_mptr = sigmas_mptr + num_cols * 0x20;
        let z_next_mptr = z_cur_mptr + num_sets * 0x20;
        let z_last_mptr = z_next_mptr + num_sets * 0x20;
        let delta_base_mptr = z_last_mptr + num_sets.saturating_sub(1) * 0x20;
        let delta_chunk = Fq::DELTA.pow_vartime([chunk_len as u64]);
        let delta_chunk = u256_string(fe_to_u256::<Fq>(&delta_chunk));
        let delta = fr_delta_literal();

        let mut block = Vec::new();
        block.push("{".to_string());
        block.push(format!("let delta := {delta}"));
        block.push(format!("let q_perm_vals := {vals_mptr:#x}"));
        block.push(format!("let q_perm_sigmas := {sigmas_mptr:#x}"));
        block.push(format!("let q_perm_z_cur := {z_cur_mptr:#x}"));
        block.push(format!("let q_perm_z_next := {z_next_mptr:#x}"));
        block.push(format!("let q_perm_z_last := {z_last_mptr:#x}"));
        block.push(format!("let q_perm_delta_base_ptr := {delta_base_mptr:#x}"));
        block.push(format!("let q_perm_num_cols := {num_cols}"));
        block.push(format!("let q_perm_num_sets := {num_sets}"));
        block.push(format!("let q_perm_chunk_len := {chunk_len}"));
        block.push(format!("let q_perm_delta_chunk := {delta_chunk}"));

        let mut value_entries = Vec::with_capacity(num_cols);
        let mut sigma_entries = Vec::with_capacity(num_cols);
        for (idx, column) in meta.permutation_columns.iter().enumerate() {
            let offset = idx * 0x20;
            let value = evaluator.eval_at(column, 0);
            let sigma = data
                .permutation_evals
                .get(column)
                .expect("permutation sigma eval present")
                .to_string();
            value_entries.push((offset, value));
            sigma_entries.push((offset, sigma));
        }
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_vals",
            &value_entries,
            "q_perm_val_load",
        );
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_sigmas",
            &sigma_entries,
            "q_perm_sigma_load",
        );

        let mut z_cur_entries = Vec::with_capacity(data.permutation_z_evals.len());
        let mut z_next_entries = Vec::with_capacity(data.permutation_z_evals.len());
        let mut z_last_entries = Vec::with_capacity(data.permutation_z_evals.len());
        for (idx, (z_cur, z_next, z_last)) in data.permutation_z_evals.iter().enumerate() {
            let offset = idx * 0x20;
            z_cur_entries.push((offset, z_cur.to_string()));
            z_next_entries.push((offset, z_next.to_string()));
            if let Some(z_last) = z_last {
                z_last_entries.push((offset, z_last.to_string()));
            }
        }
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_z_cur",
            &z_cur_entries,
            "q_perm_z_cur_load",
        );
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_z_next",
            &z_next_entries,
            "q_perm_z_next_load",
        );
        Self::push_mstore_mload_literal_runs(
            &mut block,
            "q_perm_z_last",
            &z_last_entries,
            "q_perm_z_last_load",
        );

        let fold_eval = |block: &mut Vec<String>| {
            Self::push_quotient_trace(block, state_slots, "q_perm_eval", trace);
            Self::push_structured_fold_advance(
                block,
                1,
                sorted_simple,
                "q_perm_fold_i",
                state_slots,
            );
            Self::push_quotient_eval_numer_add(block, state_slots, "q_perm_eval");
        };

        block.push("let q_perm_eval := 0".to_string());

        block.push(
            "q_perm_eval := mulmod(mload(L_0_MPTR), addmod(1, sub(r, mload(q_perm_z_cur)), r), r)"
                .to_string(),
        );
        fold_eval(&mut block);

        let final_z_offset = (num_sets - 1) * 0x20;
        block.push(format!(
            "let q_perm_zn := mload(add(q_perm_z_cur, {final_z_offset:#x}))"
        ));
        block.push(
            "q_perm_eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(q_perm_zn, q_perm_zn, r), sub(r, q_perm_zn), r), r)"
                .to_string(),
        );
        fold_eval(&mut block);

        if num_sets > 1 {
            block.push(format!(
                "for {{ let q_perm_i := 1 }} lt(q_perm_i, {num_sets}) {{ q_perm_i := add(q_perm_i, 1) }} {{"
            ));
            block.push("let q_perm_cur := mload(add(q_perm_z_cur, shl(5, q_perm_i)))".to_string());
            block.push(
                "let q_perm_prev := mload(add(q_perm_z_last, shl(5, sub(q_perm_i, 1))))"
                    .to_string(),
            );
            block.push(
                "q_perm_eval := mulmod(mload(L_0_MPTR), addmod(q_perm_cur, sub(r, q_perm_prev), r), r)"
                    .to_string(),
            );
            fold_eval(&mut block);
            block.push("}".to_string());
        }

        block.push(
            "mstore(q_perm_delta_base_ptr, mulmod(mload(BETA_MPTR), mload(X_MPTR), r))".to_string(),
        );
        block.push(format!(
            "for {{ let q_perm_set := 0 }} lt(q_perm_set, {num_sets}) {{ q_perm_set := add(q_perm_set, 1) }} {{"
        ));
        block.push("let q_perm_start := mul(q_perm_set, q_perm_chunk_len)".to_string());
        block.push("let q_perm_end := add(q_perm_start, q_perm_chunk_len)".to_string());
        block.push(
            "if gt(q_perm_end, q_perm_num_cols) { q_perm_end := q_perm_num_cols }".to_string(),
        );
        block.push("let q_perm_left := mload(add(q_perm_z_next, shl(5, q_perm_set)))".to_string());
        block.push("let q_perm_right := mload(add(q_perm_z_cur, shl(5, q_perm_set)))".to_string());
        block.push("let q_perm_delta_pow := mload(q_perm_delta_base_ptr)".to_string());
        block.push("for { let q_perm_j := q_perm_start } lt(q_perm_j, q_perm_end) { q_perm_j := add(q_perm_j, 1) } {".to_string());
        block.push("let q_perm_off := shl(5, q_perm_j)".to_string());
        block.push("let q_perm_v := mload(add(q_perm_vals, q_perm_off))".to_string());
        block.push("let q_perm_s := mload(add(q_perm_sigmas, q_perm_off))".to_string());
        block.push(
            "q_perm_left := mulmod(q_perm_left, addmod(addmod(q_perm_v, mulmod(mload(BETA_MPTR), q_perm_s, r), r), mload(GAMMA_MPTR), r), r)"
                .to_string(),
        );
        block.push(
            "q_perm_right := mulmod(q_perm_right, addmod(addmod(q_perm_v, q_perm_delta_pow, r), mload(GAMMA_MPTR), r), r)"
                .to_string(),
        );
        block.push("q_perm_delta_pow := mulmod(q_perm_delta_pow, delta, r)".to_string());
        block.push("}".to_string());
        block.push(
            "q_perm_eval := mulmod(addmod(1, sub(r, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r)), r), addmod(q_perm_left, sub(r, q_perm_right), r), r)"
                .to_string(),
        );
        fold_eval(&mut block);
        block.push(
            "mstore(q_perm_delta_base_ptr, mulmod(mload(q_perm_delta_base_ptr), q_perm_delta_chunk, r))".to_string(),
        );
        block.push("}".to_string());

        block.push("}".to_string());
        Some(block)
    }

    #[allow(clippy::too_many_arguments)]
    /// Emit a native structured loop for all LogUp lookup identities.
    ///
    /// This adapts the upstream LogUp helper and accumulator constraints while
    /// staging parallel lookup products in scratch to avoid repeated generated
    /// straight-line Yul.
    fn structured_lookup_loop_block(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
        evaluator: &Evaluator<'_>,
        sorted_simple: &[usize],
        scratch_mptr: usize,
        state_slots: Option<QuotientStateSlots>,
        trace: bool,
    ) -> Option<Vec<String>> {
        if meta.num_lookups == 0 {
            return None;
        }

        let mut max_parallel = 1usize;
        for lookup in self.vk.cs().lookups() {
            let chunked = lookup.chunk_by_degree(self.vk.cs().degree());
            for input_chunk in chunked.input_expression_chunks() {
                max_parallel = max_parallel.max(input_chunk.len());
            }
        }

        let f_plus_beta_mptr = scratch_mptr;
        let prefix_mptr = f_plus_beta_mptr + max_parallel * 0x20;
        let suffix_mptr = prefix_mptr + max_parallel * 0x20;

        let mut block = Vec::new();
        block.push("{".to_string());
        block.push(format!("let q_lookup_f := {f_plus_beta_mptr:#x}"));
        block.push(format!("let q_lookup_prefix := {prefix_mptr:#x}"));
        block.push(format!("let q_lookup_suffix := {suffix_mptr:#x}"));
        block.push("let q_lookup_l0 := mload(L_0_MPTR)".to_string());
        block.push("let q_lookup_llast := mload(L_LAST_MPTR)".to_string());
        block.push("let q_lookup_lblind := mload(L_BLIND_MPTR)".to_string());
        block.push("let q_lookup_lsum := addmod(q_lookup_l0, q_lookup_llast, r)".to_string());
        block.push(
            "let q_lookup_active := addmod(1, sub(r, addmod(q_lookup_llast, q_lookup_lblind, r)), r)"
                .to_string(),
        );
        block.push("let q_lookup_beta := mload(BETA_MPTR)".to_string());
        block.push("let q_lookup_theta := mload(THETA_MPTR)".to_string());

        for (lookup_idx, lookup) in self.vk.cs().lookups().iter().enumerate() {
            let chunked = lookup.chunk_by_degree(self.vk.cs().degree());
            let (m_eval, h_evals, z_eval, z_next_eval) = &data.lookup_evals[lookup_idx];

            block.push("{".to_string());

            // boundary = (l_0 + l_last) * Z_lookup(x)
            block.push("{".to_string());
            block.push(format!(
                "let q_lookup_eval := mulmod(q_lookup_lsum, {}, r)",
                z_eval
            ));
            Self::push_structured_main_fold(
                &mut block,
                "q_lookup_eval",
                sorted_simple,
                state_slots,
                trace,
            );
            block.push("}".to_string());

            for (input_chunk, h_eval) in
                chunked.input_expression_chunks().iter().zip(h_evals.iter())
            {
                let k = input_chunk.len();
                block.push("{".to_string());

                if k == 0 {
                    block.push("let q_lookup_eval := 0".to_string());
                    Self::push_structured_main_fold(
                        &mut block,
                        "q_lookup_eval",
                        sorted_simple,
                        state_slots,
                        trace,
                    );
                    block.push("}".to_string());
                    continue;
                }

                if k == 1 {
                    evaluator.reset_locals();
                    let (mut compressed_lines, compressed_var) = evaluator
                        .compress_expressions_with_challenge_var(&input_chunk[0], "q_lookup_theta");
                    block.append(&mut compressed_lines);
                    block.push(format!(
                        "let q_lookup_eval := addmod(mulmod({}, addmod({compressed_var}, q_lookup_beta, r), r), sub(r, 1), r)",
                        h_eval
                    ));
                    Self::push_structured_main_fold(
                        &mut block,
                        "q_lookup_eval",
                        sorted_simple,
                        state_slots,
                        trace,
                    );
                    block.push("}".to_string());
                    continue;
                }

                evaluator.reset_locals();
                if let Some(mut shared_prefix_lines) = evaluator.lookup_shared_prefix_f_plus_beta(
                    input_chunk,
                    "q_lookup_theta",
                    "q_lookup_beta",
                    "q_lookup_f",
                ) {
                    block.append(&mut shared_prefix_lines);
                } else {
                    for (input_idx, parallel_input) in input_chunk.iter().enumerate() {
                        let (mut compressed_lines, compressed_var) = evaluator
                            .compress_expressions_with_challenge_var(
                                parallel_input,
                                "q_lookup_theta",
                            );
                        block.append(&mut compressed_lines);
                        block.push(format!(
                            "mstore(add(q_lookup_f, {:#x}), addmod({compressed_var}, q_lookup_beta, r))",
                            input_idx * 0x20
                        ));
                    }
                }

                block.push("let q_lookup_product := 1".to_string());
                block.push(format!(
                    "for {{ let q_lookup_prod_i := 0 }} lt(q_lookup_prod_i, {k}) {{ q_lookup_prod_i := add(q_lookup_prod_i, 1) }} {{"
                ));
                block.push(
                    "q_lookup_product := mulmod(q_lookup_product, mload(add(q_lookup_f, shl(5, q_lookup_prod_i))), r)"
                        .to_string(),
                );
                block.push("}".to_string());

                block.push("mstore(q_lookup_prefix, 1)".to_string());
                if k > 1 {
                    block.push(format!(
                        "for {{ let q_lookup_pref_i := 1 }} lt(q_lookup_pref_i, {k}) {{ q_lookup_pref_i := add(q_lookup_pref_i, 1) }} {{"
                    ));
                    block.push("let q_lookup_pref_prev := sub(q_lookup_pref_i, 1)".to_string());
                    block.push(
                        "mstore(add(q_lookup_prefix, shl(5, q_lookup_pref_i)), mulmod(mload(add(q_lookup_prefix, shl(5, q_lookup_pref_prev))), mload(add(q_lookup_f, shl(5, q_lookup_pref_prev))), r))"
                            .to_string(),
                    );
                    block.push("}".to_string());
                }

                block.push(format!(
                    "mstore(add(q_lookup_suffix, {:#x}), 1)",
                    (k - 1) * 0x20
                ));
                if k > 1 {
                    block.push(format!(
                        "for {{ let q_lookup_suf_i := sub({k}, 1) }} gt(q_lookup_suf_i, 0) {{ q_lookup_suf_i := sub(q_lookup_suf_i, 1) }} {{"
                    ));
                    block.push("let q_lookup_suf_prev := sub(q_lookup_suf_i, 1)".to_string());
                    block.push(
                        "mstore(add(q_lookup_suffix, shl(5, q_lookup_suf_prev)), mulmod(mload(add(q_lookup_suffix, shl(5, q_lookup_suf_i))), mload(add(q_lookup_f, shl(5, q_lookup_suf_i))), r))"
                            .to_string(),
                    );
                    block.push("}".to_string());
                }

                block.push("let q_lookup_sum := 0".to_string());
                block.push(format!(
                    "for {{ let q_lookup_sum_i := 0 }} lt(q_lookup_sum_i, {k}) {{ q_lookup_sum_i := add(q_lookup_sum_i, 1) }} {{"
                ));
                block.push(
                    "q_lookup_sum := addmod(q_lookup_sum, mulmod(mload(add(q_lookup_prefix, shl(5, q_lookup_sum_i))), mload(add(q_lookup_suffix, shl(5, q_lookup_sum_i))), r), r)"
                        .to_string(),
                );
                block.push("}".to_string());
                block.push(format!(
                    "let q_lookup_eval := addmod(mulmod({}, q_lookup_product, r), sub(r, q_lookup_sum), r)",
                    h_eval
                ));
                Self::push_structured_main_fold(
                    &mut block,
                    "q_lookup_eval",
                    sorted_simple,
                    state_slots,
                    trace,
                );
                block.push("}".to_string());
            }

            // accumulator =
            // active * ((Z_next - Z - selector * sum(h)) * (table + beta) + m)
            block.push("{".to_string());
            let sum_h_expr = if h_evals.is_empty() {
                "0".to_string()
            } else {
                let sum_h = "q_lookup_sum_h";
                block.push(format!("let {sum_h} := {}", h_evals[0]));
                for h_eval in &h_evals[1..] {
                    block.push(format!("{sum_h} := addmod({sum_h}, {}, r)", h_eval));
                }
                sum_h.to_string()
            };

            evaluator.reset_locals();
            let (mut selector_lines, selector_var) =
                evaluator.evaluate_expression(chunked.selector_expression());
            block.append(&mut selector_lines);
            let (mut table_lines, table_var) = evaluator.compress_expressions_with_challenge_var(
                chunked.table_expressions(),
                "q_lookup_theta",
            );
            block.append(&mut table_lines);
            block.push(format!(
                "let q_lookup_s_sum_h := mulmod({selector_var}, {sum_h_expr}, r)"
            ));
            block.push(format!(
                "let q_lookup_diff := addmod({}, sub(r, addmod({}, q_lookup_s_sum_h, r)), r)",
                z_next_eval, z_eval
            ));
            block.push(format!(
                "let q_lookup_t_beta := addmod({table_var}, q_lookup_beta, r)"
            ));
            block.push(format!(
                "let q_lookup_core := addmod(mulmod(q_lookup_diff, q_lookup_t_beta, r), {}, r)",
                m_eval
            ));
            block
                .push("let q_lookup_eval := mulmod(q_lookup_active, q_lookup_core, r)".to_string());
            Self::push_structured_main_fold(
                &mut block,
                "q_lookup_eval",
                sorted_simple,
                state_slots,
                trace,
            );
            block.push("}".to_string());

            block.push("}".to_string());
        }

        block.push("}".to_string());
        Some(block)
    }

    /// Emit a native structured loop for the trash identity suffix.
    ///
    /// Trash constraints compress their expressions with `trash_challenge` and
    /// subtract `(1 - selector) * trash_eval`, matching the Rust trash verifier.
    fn structured_trash_loop_block(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
        evaluator: &Evaluator<'_>,
        sorted_simple: &[usize],
        state_slots: Option<QuotientStateSlots>,
        trace: bool,
    ) -> Option<Vec<String>> {
        if meta.num_trashcans == 0 {
            return None;
        }

        let mut block = Vec::new();
        block.push("{".to_string());
        block.push("let q_trash_tau := mload(TRASH_CHALLENGE_MPTR)".to_string());

        for (idx, argument) in self.vk.cs().trashcans().iter().enumerate() {
            block.push("{".to_string());
            evaluator.reset_locals();
            let (mut compressed_lines, compressed_var) = evaluator
                .compress_expressions_with_challenge_var(
                    argument.constraint_expressions(),
                    "q_trash_tau",
                );
            block.append(&mut compressed_lines);
            let (mut selector_lines, selector_var) =
                evaluator.evaluate_expression(argument.selector());
            block.append(&mut selector_lines);
            block.push(format!(
                "let q_trash_one_minus_selector := addmod(1, sub(r, {selector_var}), r)"
            ));
            block.push(format!(
                "let q_trash_scaled := mulmod(q_trash_one_minus_selector, {}, r)",
                data.trashcan_evals[idx]
            ));
            block.push(format!(
                "let q_trash_eval := addmod({compressed_var}, sub(r, q_trash_scaled), r)"
            ));
            Self::push_structured_main_fold(
                &mut block,
                "q_trash_eval",
                sorted_simple,
                state_slots,
                trace,
            );
            block.push("}".to_string());
        }

        block.push("}".to_string());
        Some(block)
    }

    /// Emit the fully structured quotient path used for experiments.
    ///
    /// Gates are still emitted directly, but permutation, lookup, and trash
    /// identities can be grouped into loops while preserving the global y-fold.
    fn structured_loop_quotient_computations(
        &self,
        meta: &ConstraintSystemMeta,
        data: &Data,
        sorted_simple: &[usize],
        scratch_mptr: usize,
        trace: bool,
    ) -> Vec<Vec<String>> {
        let evaluator = Evaluator::new(self.vk.cs(), meta, data).with_pow5_helper(true);
        let eval_scratch_slot =
            scratch_mptr + Self::structured_permutation_scratch_words(meta) * 0x20;
        let gate_items = evaluator.gate_computations_tagged();

        let mut init = vec!["let quotient_eval_numer := 0".to_string()];
        if !sorted_simple.is_empty() {
            init.push(format!(
                "for {{ let q_sel_zero_off := 0 }} lt(q_sel_zero_off, {:#x}) {{ q_sel_zero_off := add(q_sel_zero_off, 0x20) }} {{",
                sorted_simple.len() * 0x20
            ));
            init.push("mstore(add(SELECTOR_ACC_MPTR, q_sel_zero_off), 0)".to_string());
            init.push("}".to_string());
        }
        if !sorted_simple.is_empty() {
            init.push("let q_sel_scale := 1".to_string());
            init.push("let q_sel_inv_scale := 1".to_string());
            init.push("let q_y_inv := 0".to_string());
            init.push("{".to_string());
            init.push(format!("let q_inv_scratch := {eval_scratch_slot:#x}"));
            init.push("if iszero(y) { revert(0, 0) }".to_string());
            init.push(format!(
                "mstore(add(q_inv_scratch, {:#x}), {:#x})",
                layout::modexp_frame::BASE_LEN_OFFSET,
                layout::WORD_BYTES
            ));
            init.push(format!(
                "mstore(add(q_inv_scratch, {:#x}), {:#x})",
                layout::modexp_frame::EXP_LEN_OFFSET,
                layout::WORD_BYTES
            ));
            init.push(format!(
                "mstore(add(q_inv_scratch, {:#x}), {:#x})",
                layout::modexp_frame::MOD_LEN_OFFSET,
                layout::WORD_BYTES
            ));
            init.push(format!(
                "mstore(add(q_inv_scratch, {:#x}), y)",
                layout::modexp_frame::BASE_OFFSET
            ));
            init.push(format!(
                "mstore(add(q_inv_scratch, {:#x}), sub(FR_MODULUS, 2))",
                layout::modexp_frame::EXP_OFFSET
            ));
            init.push(format!(
                "mstore(add(q_inv_scratch, {:#x}), FR_MODULUS)",
                layout::modexp_frame::MOD_OFFSET
            ));
            init.push(format!(
                "if iszero(staticcall(gas(), {:#x}, q_inv_scratch, {:#x}, q_inv_scratch, {:#x})) {{ revert(0, 0) }}",
                layout::precompile::MODEXP_ADDRESS,
                layout::MODEXP_FRAME_BYTES,
                layout::WORD_BYTES
            ));
            init.push(format!(
                "if iszero(eq(returndatasize(), {:#x})) {{ revert(0, 0) }}",
                layout::WORD_BYTES
            ));
            init.push("q_y_inv := mload(q_inv_scratch)".to_string());
            init.push("}".to_string());
        }
        let mut computations = vec![init];

        let mut pending_selector = None;
        let mut pending_selector_run: Vec<(Vec<String>, String)> = Vec::new();
        for item in gate_items {
            let target = match item.simple_selector_index {
                Some(col) => {
                    let idx = sorted_simple
                        .iter()
                        .position(|simple| *simple == col)
                        .expect("selector column present");
                    QuotientTarget::Selector(idx)
                }
                None => QuotientTarget::Main,
            };
            match target {
                QuotientTarget::Selector(idx) => {
                    if pending_selector == Some(idx) {
                        pending_selector_run.push((item.lines, item.var));
                    } else {
                        Self::flush_structured_selector_run(
                            &mut computations,
                            &mut pending_selector,
                            &mut pending_selector_run,
                            sorted_simple,
                            eval_scratch_slot,
                            None,
                            trace,
                        );
                        pending_selector = Some(idx);
                        pending_selector_run.push((item.lines, item.var));
                    }
                }
                QuotientTarget::Main => {
                    Self::flush_structured_selector_run(
                        &mut computations,
                        &mut pending_selector,
                        &mut pending_selector_run,
                        sorted_simple,
                        eval_scratch_slot,
                        None,
                        trace,
                    );
                    computations.push(Self::direct_quotient_block(
                        &item.lines,
                        &item.var,
                        target,
                        None,
                        sorted_simple,
                        eval_scratch_slot,
                        None,
                        trace,
                    ));
                }
            }
        }
        Self::flush_structured_selector_run(
            &mut computations,
            &mut pending_selector,
            &mut pending_selector_run,
            sorted_simple,
            eval_scratch_slot,
            None,
            trace,
        );

        if let Some(block) = Self::structured_permutation_loop_block(
            meta,
            data,
            &evaluator,
            sorted_simple,
            scratch_mptr,
            None,
            trace,
        ) {
            computations.push(block);
        }

        if let Some(block) = self.structured_lookup_loop_block(
            meta,
            data,
            &evaluator,
            sorted_simple,
            eval_scratch_slot,
            None,
            trace,
        ) {
            computations.push(block);
        }

        if let Some(block) =
            self.structured_trash_loop_block(meta, data, &evaluator, sorted_simple, None, trace)
        {
            computations.push(block);
        }

        if !sorted_simple.is_empty() {
            let mut tail = Vec::new();
            tail.push(format!(
                "for {{ let q_sel_tail_off := 0 }} lt(q_sel_tail_off, {:#x}) {{ q_sel_tail_off := add(q_sel_tail_off, 0x20) }} {{",
                sorted_simple.len() * 0x20
            ));
            tail.push(
                "mstore(add(SELECTOR_ACC_MPTR, q_sel_tail_off), mulmod(mload(add(SELECTOR_ACC_MPTR, q_sel_tail_off)), q_sel_scale, r))"
                    .to_string(),
            );
            tail.push("}".to_string());
            computations.push(tail);
        }

        computations
    }

    /// Build the Askama model for the standalone quotient evaluator contract.
    fn generate_quotient_evaluator(&self, trace: bool) -> Halo2QuotientEvaluator {
        let proof_cptr = Ptr::calldata(layout::abi::VERIFY_PROOF_PROOF_CPTR);

        let vk = self.generate_vk();
        let vk_len = vk.len();
        let (vk_mptr, meta, data, _) = self.meta_data_for_stable_static_layout(&vk, proof_cptr);
        let quotient_plan = self.quotient_program_plan(&meta, &data);
        let sorted_simple = quotient_plan.sorted_simple.clone();

        assert!(
            !(quotient_inline_cse_enabled() && quotient_structured_loops_enabled()),
            "{QUOTIENT_CSE_ENV}=1 and {QUOTIENT_STRUCTURED_LOOPS_ENV}=1 are mutually exclusive"
        );
        assert!(
            !(quotient_inline_cse_enabled() || quotient_structured_loops_enabled()),
            "external quotient evaluator is only implemented for the compact VM quotient path"
        );

        let quotient_program_build =
            self.build_quotient_program_items(&quotient_plan.items, &quotient_plan.selector_fold);
        let native_callback_scratch_words =
            self.native_callback_scratch_words(&meta, &quotient_plan);
        let quotient_stack_words = Self::quotient_stack_words_for_build(
            &quotient_program_build,
            native_callback_scratch_words,
        );
        let quotient_state_words = Self::quotient_state_words(&quotient_plan.selector_fold);
        let memory = self.memory_layout_for(
            &meta,
            &vk,
            vk_mptr,
            VerifierMemoryLayoutConfig {
                quotient_cse_temps: quotient_program_build.cse_temps + quotient_state_words,
                quotient_stack_words,
                ..VerifierMemoryLayoutConfig::default()
            },
        );
        let selector_acc_mptr = memory.selector_acc_mptr;
        let quotient_tmp_mptr = memory.quotient_tmp_mptr;
        let quotient_program_chunks =
            PackedProgramCodec::encode_words(&quotient_program_build.bytes);
        let quotient_const_words = vk.quotient_const_words;
        let quotient_program_words = vk.quotient_program_words;
        let quotient_const_offset_words = vk
            .quotient_const_offset_words
            .expect("VK must carry quotient constants");
        let quotient_program_offset_words = vk
            .quotient_program_offset_words
            .expect("VK must carry quotient program");
        assert!(
            quotient_program_build.consts.len() <= quotient_const_words,
            "quotient const table exceeded VK payload reservation"
        );
        assert!(
            quotient_program_chunks.len() <= quotient_program_words,
            "quotient program length exceeded VK payload reservation"
        );
        let quotient_stack_mptr = memory.quotient_stack_mptr;
        let const_mptr = (vk_mptr + quotient_const_offset_words).value().as_usize();
        let program_mptr = (vk_mptr + quotient_program_offset_words).value().as_usize();
        let quotient_state_slots =
            QuotientStateSlots::new(quotient_tmp_mptr, quotient_program_build.cse_temps);
        let quotient_program = Some(QuotientProgram {
            consts: quotient_program_build.consts,
            chunks: quotient_program_chunks,
            len: quotient_program_build.bytes.len(),
            packed32: quotient_program_build.packed32,
            cse_temps: quotient_program_build.cse_temps,
            op_usage: Self::quotient_opcode_usage(&quotient_program_build.used_ops),
            mem_usage: Self::quotient_mem_usage(&quotient_program_build.used_mem_tokens),
            const_mptr,
            tmp_mptr: quotient_tmp_mptr,
            eval_numer_mptr: quotient_state_slots.eval_numer_mptr,
            trace_id_mptr: quotient_state_slots.trace_id_mptr,
            selector_power_mptr: quotient_state_slots.selector_power_mptr,
            selector_max_power: quotient_plan.selector_fold.max_power,
            selector_tail_updates: Self::selector_tail_updates(&quotient_plan.selector_fold),
            stack_mptr: quotient_stack_mptr,
            program_mptr,
        });

        let mut quotient_inline_computations = Vec::new();
        let quotient_eval_numer_computations = Vec::new();
        let mut quotient_post_vm_computations = Vec::new();
        let mut quotient_native_permutation_computation = Vec::new();
        let mut quotient_native_lookup_computation = Vec::new();
        let mut quotient_native_identity_computations = Vec::new();
        let quotient_native_trash_computation = Vec::new();

        // Inline/native quotient blocks reuse the VM stack base as expression
        // scratch. For native permutation this means the planner's
        // `quotient_stack_words` reservation must cover the structured table
        // size, not just the interpreted stack high-water mark.
        let eval_scratch_slot = quotient_stack_mptr;
        let evaluator = Evaluator::new(self.vk.cs(), &meta, &data).with_pow5_helper(true);
        for identity in &quotient_plan.inline_identities {
            quotient_inline_computations.push(Self::direct_quotient_block(
                &identity.lines,
                &identity.var,
                identity.target,
                quotient_plan.selector_fold.gap_for(identity),
                &sorted_simple,
                eval_scratch_slot,
                Some(quotient_state_slots),
                trace,
            ));
        }
        if quotient_plan.has_native_permutation {
            if let Some(block) = Self::structured_permutation_loop_block(
                &meta,
                &data,
                &evaluator,
                &sorted_simple,
                quotient_stack_mptr,
                Some(quotient_state_slots),
                trace,
            ) {
                quotient_native_permutation_computation = block;
            }
        }
        if quotient_plan.has_native_lookup {
            if let Some(block) = self.structured_lookup_loop_block(
                &meta,
                &data,
                &evaluator,
                &sorted_simple,
                quotient_stack_mptr,
                Some(quotient_state_slots),
                trace,
            ) {
                quotient_native_lookup_computation = block;
            }
        }
        for identity in &quotient_plan.native_identities {
            quotient_native_identity_computations.push(Self::direct_quotient_block(
                &identity.lines,
                &identity.var,
                identity.target,
                quotient_plan.selector_fold.gap_for(identity),
                &sorted_simple,
                eval_scratch_slot,
                Some(quotient_state_slots),
                trace,
            ));
        }
        if quotient_structured_tail_mode() == QuotientStructuredTailMode::Trash
            && meta.num_trashcans > 0
        {
            if let Some(block) = self.structured_trash_loop_block(
                &meta,
                &data,
                &evaluator,
                &sorted_simple,
                Some(quotient_state_slots),
                trace,
            ) {
                quotient_post_vm_computations.push(block);
            }
        }

        let quotient_pow5_helper = quotient_inline_computations
            .iter()
            .chain(quotient_post_vm_computations.iter())
            .chain(std::iter::once(&quotient_native_permutation_computation))
            .chain(std::iter::once(&quotient_native_lookup_computation))
            .chain(quotient_native_identity_computations.iter())
            .chain(std::iter::once(&quotient_native_trash_computation))
            .flat_map(|block| block.iter())
            .any(|line| line.contains("q_pow5("));
        let quotient_limb7_helper = quotient_inline_computations
            .iter()
            .chain(quotient_post_vm_computations.iter())
            .chain(std::iter::once(&quotient_native_permutation_computation))
            .chain(std::iter::once(&quotient_native_lookup_computation))
            .chain(quotient_native_identity_computations.iter())
            .chain(std::iter::once(&quotient_native_trash_computation))
            .flat_map(|block| block.iter())
            .any(|line| line.contains("q_limb7("));
        let quotient_wide_limb7_helper = quotient_inline_computations
            .iter()
            .chain(quotient_post_vm_computations.iter())
            .chain(std::iter::once(&quotient_native_permutation_computation))
            .chain(std::iter::once(&quotient_native_lookup_computation))
            .chain(quotient_native_identity_computations.iter())
            .chain(std::iter::once(&quotient_native_trash_computation))
            .flat_map(|block| block.iter())
            .any(|line| line.contains("q_limb7_wide("));
        let quotient_external =
            Self::quotient_external_frame(vk_mptr, vk_len, &meta, &memory, sorted_simple.len());

        let quotient_evaluator = Halo2QuotientEvaluator {
            template_constants: Default::default(),
            trace,
            quotient_yul_helpers: false,
            quotient_pow5_helper,
            quotient_limb7_helper,
            quotient_wide_limb7_helper,
            limb7_yul_coeffs: LIMB7_YUL_COEFFS,
            wide_limb7_yul_coeffs: WIDE_LIMB7_YUL_COEFFS,
            fr_delta: fr_delta_literal(),
            memory,
            vk_mptr,
            vk_len,
            challenge_mptr: data.challenge_mptr,
            num_user_challenges: meta.num_user_challenges.iter().sum(),
            theta_mptr: data.theta_mptr,
            reversed_evals_mptr: data.reversed_evals_mptr,
            num_evals: meta.num_evals,
            selector_acc_mptr,
            quotient_external,
            quotient_inline_computations,
            quotient_eval_numer_computations,
            quotient_post_vm_computations,
            quotient_native_permutation_computation,
            quotient_native_lookup_computation,
            quotient_native_identity_computations,
            quotient_native_trash_computation,
            quotient_program,
            simple_selector_cols: sorted_simple,
            quotient_identity_trace_base: layout::trace::QUOTIENT_IDENTITY_BASE,
        };
        quotient_evaluator
            .validate_layout()
            .unwrap_or_else(|err| panic!("invalid generated quotient evaluator layout: {err}"));
        quotient_evaluator
    }

    /// Build the Askama model for the main Solidity verifier contract.
    ///
    /// This is the central assembly point: it fixes proof calldata, VK bytes,
    /// memory layout, quotient representation, PCS computations, accumulator
    /// metadata, trace settings, and optional external quotient pinning before
    /// handing immutable data to the template.
    fn generate_verifier(
        &self,
        separate: bool,
        trace: bool,
        gas_checkpoints: bool,
        external_quotient: bool,
        expected_quotient: Option<(usize, U256)>,
    ) -> Halo2Verifier {
        assert!(
            expected_quotient.is_none() || external_quotient,
            "quotient pinning requires an external quotient evaluator"
        );
        assert!(
            !external_quotient || expected_quotient.is_some(),
            "external quotient evaluator render requires a generated runtime length/codehash; \
             render the quotient evaluator first and use the pinned quotient render API"
        );
        let proof_cptr = Ptr::calldata(layout::abi::VERIFY_PROOF_PROOF_CPTR);

        let vk = self.generate_vk();
        let (vk_mptr, meta, data, _) = self.meta_data_for_stable_static_layout(&vk, proof_cptr);

        let quotient_plan = self.quotient_program_plan(&meta, &data);
        let identities = self.quotient_identity_parts(&meta, &data).all_identities();
        let sorted_simple = quotient_plan.sorted_simple.clone();
        let use_inline_cse = quotient_inline_cse_enabled();
        let use_structured_loops = quotient_structured_loops_enabled();
        assert!(
            !(use_inline_cse && use_structured_loops),
            "{QUOTIENT_CSE_ENV}=1 and {QUOTIENT_STRUCTURED_LOOPS_ENV}=1 are mutually exclusive"
        );
        let quotient_yul_helpers = use_inline_cse && quotient_yul_helpers_enabled();
        let quotient_program_build = (!(use_inline_cse || use_structured_loops)).then(|| {
            self.build_quotient_program_items(&quotient_plan.items, &quotient_plan.selector_fold)
        });

        let lookup_helper_chunks_total: usize = meta.lookup_chunks.iter().sum();
        let total_advices: usize = meta.num_user_advices.iter().sum();
        let acc_msm_terms = self
            .acc_encoding
            .map(|acc_encoding| {
                let fixed_scalar_count = acc_encoding
                    .fixed_scalar_count(self.num_instances)
                    .expect("accumulator encoding validated by set_acc_encoding");
                fixed_scalar_count + 1
            })
            .unwrap_or(0);
        let pcs_memory_requirements = pcs::memory_requirements(&meta, &data);
        let quotient_cse_temps = quotient_program_build
            .as_ref()
            .map(|build| build.cse_temps + Self::quotient_state_words(&quotient_plan.selector_fold))
            .unwrap_or(0);
        let quotient_stack_words = quotient_program_build
            .as_ref()
            .map(|build| {
                let native_callback_scratch_words =
                    self.native_callback_scratch_words(&meta, &quotient_plan);
                Self::quotient_stack_words_for_build(build, native_callback_scratch_words)
            })
            .unwrap_or(0);
        let memory = self.memory_layout_for(
            &meta,
            &vk,
            vk_mptr,
            VerifierMemoryLayoutConfig {
                quotient_cse_temps,
                quotient_stack_words,
                acc_msm_terms,
                pcs: pcs_memory_requirements,
                ..VerifierMemoryLayoutConfig::default()
            },
        );
        let selector_acc_mptr = memory.selector_acc_mptr;
        let batch_invert_scratch_mptr = memory.batch_invert_scratch_mptr;
        let expected_vk_codehash = separate.then(|| {
            let digest: [u8; 32] = Keccak256::digest(vk.runtime_bytes()).into();
            U256::from_be_bytes(digest)
        });
        let vk_len = vk.len();
        let quotient_tmp_mptr = memory.quotient_tmp_mptr;
        let proof_layout = ProofCalldataLayout::from_protocol(
            &meta.protocol,
            proof_cptr.value().as_usize(),
            meta.num_evals,
            meta.num_point_sets,
        );
        let transcript_layout = Self::transcript_buffer_layout_for_meta(&meta, self.num_instances);
        let quotient_external = external_quotient.then(|| {
            Self::quotient_external_frame(vk_mptr, vk_len, &meta, &memory, sorted_simple.len())
        });
        let (expected_quotient_len, expected_quotient_codehash) = expected_quotient
            .map(|(len, codehash)| (Some(len), Some(codehash)))
            .unwrap_or((None, None));
        let (quotient_program, quotient_stack_mptr, quotient_state_slots) =
            if let Some(quotient_program_build) = quotient_program_build {
                let quotient_program_chunks =
                    PackedProgramCodec::encode_words(&quotient_program_build.bytes);
                let quotient_const_words = vk.quotient_const_words;
                let quotient_program_words = vk.quotient_program_words;
                let quotient_const_offset_words = vk
                    .quotient_const_offset_words
                    .expect("VK must carry quotient constants");
                let quotient_program_offset_words = vk
                    .quotient_program_offset_words
                    .expect("VK must carry quotient program");
                assert!(
                    quotient_program_build.consts.len() <= quotient_const_words,
                    "quotient const table exceeded VK payload reservation"
                );
                assert!(
                    quotient_program_chunks.len() <= quotient_program_words,
                    "quotient program length exceeded VK payload reservation"
                );
                let quotient_stack_mptr = memory.quotient_stack_mptr;
                let const_mptr = (vk_mptr + quotient_const_offset_words).value().as_usize();
                let program_mptr = (vk_mptr + quotient_program_offset_words).value().as_usize();
                let state_slots =
                    QuotientStateSlots::new(quotient_tmp_mptr, quotient_program_build.cse_temps);
                (
                    Some(QuotientProgram {
                        consts: quotient_program_build.consts,
                        chunks: quotient_program_chunks,
                        len: quotient_program_build.bytes.len(),
                        packed32: quotient_program_build.packed32,
                        cse_temps: quotient_program_build.cse_temps,
                        op_usage: Self::quotient_opcode_usage(&quotient_program_build.used_ops),
                        mem_usage: Self::quotient_mem_usage(
                            &quotient_program_build.used_mem_tokens,
                        ),
                        const_mptr,
                        tmp_mptr: quotient_tmp_mptr,
                        eval_numer_mptr: state_slots.eval_numer_mptr,
                        trace_id_mptr: state_slots.trace_id_mptr,
                        selector_power_mptr: state_slots.selector_power_mptr,
                        selector_max_power: quotient_plan.selector_fold.max_power,
                        selector_tail_updates: Self::selector_tail_updates(
                            &quotient_plan.selector_fold,
                        ),
                        stack_mptr: quotient_stack_mptr,
                        program_mptr,
                    }),
                    quotient_stack_mptr,
                    Some(state_slots),
                )
            } else {
                (None, quotient_tmp_mptr, None)
            };

        let mut quotient_inline_computations: Vec<Vec<String>> = Vec::new();
        let mut quotient_eval_numer_computations: Vec<Vec<String>> = Vec::new();
        let mut quotient_post_vm_computations: Vec<Vec<String>> = Vec::new();
        let mut quotient_native_permutation_computation: Vec<String> = Vec::new();
        let mut quotient_native_lookup_computation: Vec<String> = Vec::new();
        let mut quotient_native_identity_computations: Vec<Vec<String>> = Vec::new();
        let quotient_native_trash_computation: Vec<String> = Vec::new();

        if external_quotient {
            // The external quotient evaluator renders and runs these blocks.
            // Keep the main verifier source free of the bulky native quotient
            // code; it only performs the staticcall and copies the output.
        } else if use_structured_loops {
            quotient_eval_numer_computations = self.structured_loop_quotient_computations(
                &meta,
                &data,
                &sorted_simple,
                quotient_tmp_mptr,
                trace,
            );
        } else if use_inline_cse {
            quotient_eval_numer_computations = Self::inline_cse_quotient_computations(
                &identities,
                &sorted_simple,
                quotient_tmp_mptr,
                quotient_yul_helpers,
                trace,
            );
        } else {
            // The compact VM, inline prefix, and native callbacks share the
            // same stack/scratch base in this path. Keep memory sizing tied to
            // both `max_stack` and callback-specific scratch needs.
            let eval_scratch_slot = quotient_stack_mptr;
            let evaluator = Evaluator::new(self.vk.cs(), &meta, &data).with_pow5_helper(true);

            for identity in &quotient_plan.inline_identities {
                quotient_inline_computations.push(Self::direct_quotient_block(
                    &identity.lines,
                    &identity.var,
                    identity.target,
                    quotient_plan.selector_fold.gap_for(identity),
                    &sorted_simple,
                    eval_scratch_slot,
                    quotient_state_slots,
                    trace,
                ));
            }

            if quotient_plan.has_native_permutation {
                if let Some(block) = Self::structured_permutation_loop_block(
                    &meta,
                    &data,
                    &evaluator,
                    &sorted_simple,
                    quotient_stack_mptr,
                    quotient_state_slots,
                    trace,
                ) {
                    quotient_native_permutation_computation = block;
                }
            }

            if quotient_plan.has_native_lookup {
                if let Some(block) = self.structured_lookup_loop_block(
                    &meta,
                    &data,
                    &evaluator,
                    &sorted_simple,
                    quotient_stack_mptr,
                    quotient_state_slots,
                    trace,
                ) {
                    quotient_native_lookup_computation = block;
                }
            }

            for identity in &quotient_plan.native_identities {
                quotient_native_identity_computations.push(Self::direct_quotient_block(
                    &identity.lines,
                    &identity.var,
                    identity.target,
                    quotient_plan.selector_fold.gap_for(identity),
                    &sorted_simple,
                    eval_scratch_slot,
                    quotient_state_slots,
                    trace,
                ));
            }

            if quotient_structured_tail_mode() == QuotientStructuredTailMode::Trash
                && meta.num_trashcans > 0
            {
                if let Some(block) = self.structured_trash_loop_block(
                    &meta,
                    &data,
                    &evaluator,
                    &sorted_simple,
                    quotient_state_slots,
                    trace,
                ) {
                    quotient_post_vm_computations.push(block);
                }
            }
        }

        let quotient_pow5_helper = !external_quotient
            && quotient_eval_numer_computations
                .iter()
                .chain(quotient_inline_computations.iter())
                .chain(quotient_post_vm_computations.iter())
                .chain(std::iter::once(&quotient_native_permutation_computation))
                .chain(std::iter::once(&quotient_native_lookup_computation))
                .chain(quotient_native_identity_computations.iter())
                .chain(std::iter::once(&quotient_native_trash_computation))
                .flat_map(|block| block.iter())
                .any(|line| line.contains("q_pow5("));
        let quotient_limb7_helper = !external_quotient
            && quotient_eval_numer_computations
                .iter()
                .chain(quotient_inline_computations.iter())
                .chain(quotient_post_vm_computations.iter())
                .chain(std::iter::once(&quotient_native_permutation_computation))
                .chain(std::iter::once(&quotient_native_lookup_computation))
                .chain(quotient_native_identity_computations.iter())
                .chain(std::iter::once(&quotient_native_trash_computation))
                .flat_map(|block| block.iter())
                .any(|line| line.contains("q_limb7("));
        let quotient_wide_limb7_helper = !external_quotient
            && quotient_eval_numer_computations
                .iter()
                .chain(quotient_inline_computations.iter())
                .chain(quotient_post_vm_computations.iter())
                .chain(std::iter::once(&quotient_native_permutation_computation))
                .chain(std::iter::once(&quotient_native_lookup_computation))
                .chain(quotient_native_identity_computations.iter())
                .chain(std::iter::once(&quotient_native_trash_computation))
                .flat_map(|block| block.iter())
                .any(|line| line.contains("q_limb7_wide("));

        let pcs_computations = pcs::computations(
            &meta,
            &data,
            &memory,
            cfg!(feature = "truncated-challenges"),
            trace,
        );

        // Per-user-phase breakdown (advices + user challenges).
        let mut challenge_offset = 0usize;
        let user_phases: Vec<UserPhase> = meta
            .num_user_advices
            .iter()
            .zip(meta.num_user_challenges.iter())
            .enumerate()
            .map(|(idx, (&n_a, &n_c))| {
                let phase = UserPhase {
                    num_advices: n_a,
                    advice_bytes: proof_layout.advice_phases[idx].byte_len,
                    num_challenges: n_c,
                    challenge_offset,
                };
                challenge_offset += n_c;
                phase
            })
            .collect();
        let num_user_challenges: usize = meta.num_user_challenges.iter().sum();
        let lookup_h_plus_acc: usize = meta.lookup_chunks.iter().sum::<usize>() + meta.num_lookups;

        // Compute VK / accumulator layout helpers before moving vk into
        // the template struct.
        let fixed_comm_mptr_byte = (vk_mptr + vk.constants.len()).value().as_usize();
        let permutation_comm_mptr_byte = fixed_comm_mptr_byte + vk.fixed_comms.len() * G1_BYTES;
        let g1_base_mptr_byte = (vk_mptr + layout::VkHeaderSlot::G1Base.word())
            .value()
            .as_usize();

        let mut acc_fixed_bases: Vec<(String, usize, bool)> = Vec::new();
        if let Some(acc_encoding) = self.acc_encoding {
            let fixed_scalar_count = acc_encoding
                .fixed_scalar_count(self.num_instances)
                .expect("accumulator encoding validated by set_acc_encoding");
            // A fully-collapsed public accumulator has no fixed-base scalar
            // tail: just (lhs point, lhs scalar=1, rhs point, rhs scalar=1).
            // Older partially-collapsed accumulators still expose the RHS
            // fixed scalars for -G, fixed commitments, and permutation
            // commitments in BTreeMap key order.
            if fixed_scalar_count != 0 {
                let num_perm_bases = vk.permutation_comms.len();
                let num_fixed_bases = fixed_scalar_count
                    .checked_sub(1 + num_perm_bases)
                    .expect("accumulator fixed scalar count is smaller than -G + permutations");

                acc_fixed_bases.push(("-G".to_string(), g1_base_mptr_byte, true));
                for i in 0..num_fixed_bases {
                    acc_fixed_bases.push((
                        format!("self_vk_fixed_com_{i}"),
                        fixed_comm_mptr_byte + i * G1_BYTES,
                        false,
                    ));
                }
                for i in 0..num_perm_bases {
                    acc_fixed_bases.push((
                        format!("self_vk_perm_com_{i}"),
                        permutation_comm_mptr_byte + i * G1_BYTES,
                        false,
                    ));
                }
            }
            debug_assert_eq!(
                acc_fixed_bases.len(),
                fixed_scalar_count,
                "accumulator fixed-base scalar tail must match generated bases"
            );
        }
        acc_fixed_bases.sort_by(|a, b| a.0.cmp(&b.0));
        let acc_fixed_bases: Vec<(usize, bool)> = acc_fixed_bases
            .into_iter()
            .map(|(_, mptr, negate)| (mptr, negate))
            .collect();
        let (
            expected_has_accumulator,
            expected_acc_offset,
            expected_num_acc_limbs,
            expected_num_acc_limb_bits,
            expected_acc_has_carried_scalars,
        ) = self
            .acc_encoding
            .map(|acc_encoding| {
                (
                    true,
                    acc_encoding.offset,
                    acc_encoding.num_limbs,
                    acc_encoding.num_limb_bits,
                    acc_encoding.has_carried_scalars(),
                )
            })
            .unwrap_or((false, 0, 0, 0, false));

        let acc_msm_scratch = memory.acc_msm_scratch;
        let g1msm_single_gas_cap = layout::precompile::g1msm_gas_cap(layout::G1_MSM_PAIR_BYTES);
        let lin_trace_g1msm_gas_cap = layout::precompile::g1msm_gas_cap(
            (meta.num_quotients + sorted_simple.len()) * layout::G1_MSM_PAIR_BYTES,
        );
        // The accumulator RHS MSM always includes the carried RHS point and may
        // append generated fixed bases whose public scalars are nonzero. A max
        // cap is safe because unused precompile gas is returned, and it avoids
        // rendering the EIP-2537 discount-table switch into runtime bytecode.
        let acc_rhs_g1msm_gas_cap = layout::precompile::g1msm_gas_cap(
            (1 + acc_fixed_bases.len()) * layout::G1_MSM_PAIR_BYTES,
        );
        let final_pairing_gas_cap =
            layout::precompile::pairing_gas_cap(layout::PAIRING_TWO_PAIR_BYTES);

        let verifier = Halo2Verifier {
            template_constants: Default::default(),
            trace,
            gas_checkpoints,
            quotient_yul_helpers,
            quotient_pow5_helper,
            quotient_limb7_helper,
            quotient_wide_limb7_helper,
            g1msm_single_gas_cap,
            lin_trace_g1msm_gas_cap,
            acc_rhs_g1msm_gas_cap,
            final_pairing_gas_cap,
            limb7_yul_coeffs: LIMB7_YUL_COEFFS,
            wide_limb7_yul_coeffs: WIDE_LIMB7_YUL_COEFFS,
            fr_delta: fr_delta_literal(),
            embedded_vk: (!separate).then_some(vk),
            expected_vk_codehash,
            vk_len,
            num_instances: self.num_instances,
            k: self.vk.get_domain().k() as usize,
            codegen_layout: VerifierCodegenLayout {
                proof: proof_layout.clone(),
                memory: memory.clone(),
                vk_header: Default::default(),
                transcript: transcript_layout,
                quotient_external: quotient_external.clone(),
            },
            memory,
            vk_header: Default::default(),
            vk_mptr,
            num_neg_lagranges: meta.rotation_last.unsigned_abs() as usize,
            user_phases,
            num_user_challenges,
            num_lookups: meta.num_lookups,
            num_permutation_zs: meta.num_permutation_zs,
            lookup_h_plus_acc,
            num_trashcans: meta.num_trashcans,
            num_quotients: meta.num_quotients,
            num_evals: meta.num_evals,
            num_point_sets: meta.num_point_sets,
            total_advices,
            lookup_helper_chunks_total,
            lookup_chunks: meta.lookup_chunks.clone(),
            comms_mptr_base: data.comms_mptr_base,
            reversed_evals_mptr: data.reversed_evals_mptr,
            pcs_memory_requirements,
            selector_acc_mptr,
            batch_invert_scratch_mptr,
            quotient_external,
            expected_quotient_len,
            expected_quotient_codehash,
            proof_cptr,
            abi_selector_bytes: layout::abi::SELECTOR_BYTES,
            abi_proof_head_offset: layout::abi::VERIFY_PROOF_PROOF_HEAD_OFFSET,
            abi_instances_head_cptr: layout::abi::SELECTOR_BYTES + WORD_BYTES,
            num_instance_cptr: proof_layout.proof_end,
            instance_cptr: proof_layout.proof_end + WORD_BYTES,
            quotient_comm_cptr: Ptr::calldata(proof_layout.quotient_comm_cptr),
            proof_len: proof_layout.proof_len,
            challenge_mptr: data.challenge_mptr,
            theta_mptr: data.theta_mptr,
            quotient_inline_computations,
            quotient_eval_numer_computations,
            quotient_post_vm_computations,
            quotient_native_permutation_computation,
            quotient_native_lookup_computation,
            quotient_native_identity_computations,
            quotient_native_trash_computation,
            quotient_program: if external_quotient {
                None
            } else {
                quotient_program
            },
            pcs_computations,
            simple_selector_cols: sorted_simple.clone(),
            proof_commit_trace_base: layout::trace::PROOF_COMMIT_BASE,
            proof_eval_trace_base: layout::trace::PROOF_EVAL_BASE,
            quotient_identity_trace_base: layout::trace::QUOTIENT_IDENTITY_BASE,
            selector_trace_base: layout::trace::SELECTOR_FOLD_BASE,
            fixed_comm_mptr: fixed_comm_mptr_byte,
            truncated_challenges: cfg!(feature = "truncated-challenges"),
            fewer_point_sets: cfg!(feature = "outer-fewer-point-sets"),
            num_dummy_evals: meta.num_dummy_evals,
            expected_has_accumulator,
            expected_acc_offset,
            expected_num_acc_limbs,
            expected_num_acc_limb_bits,
            expected_acc_has_carried_scalars,
            acc_fixed_bases,
            acc_msm_scratch,
        };
        verifier
            .validate_layout()
            .unwrap_or_else(|err| panic!("invalid generated verifier layout: {err}"));
        verifier
    }

    /// Lower a logical quotient item stream into compact VM bytecode.
    fn build_quotient_program_items(
        &self,
        items: &[QuotientProgramItem],
        selector_fold: &SelectorFoldPlan,
    ) -> QuotientProgramBuild {
        let mut builder = QuotientProgramBuilder::with_limb_vm_ops(quotient_limb_vm_ops_enabled());
        // Lower the logical plan into bytecode in one pass. CSE planning looks
        // at all interpreted identities first, but native callbacks remain
        // opaque markers because their arithmetic is emitted as separate Yul
        // kernels in the template.
        // Mirror snark-verifier's loader cache shape: when VM CSE is enabled,
        // choose repeated expression temps across the whole quotient program,
        // not just within one identity.
        let mut cse = quotient_vm_cse_enabled().then(|| {
            let exprs = items
                .iter()
                .filter_map(|item| match item {
                    QuotientProgramItem::Identity(identity) => {
                        Some(Self::quotient_identity_expr(identity))
                    }
                    QuotientProgramItem::NativePermutation
                    | QuotientProgramItem::NativeLookup
                    | QuotientProgramItem::NativeIdentity(_) => None,
                })
                .collect::<Vec<_>>();
            QuotientCseState::from_exprs(&exprs)
        });

        for item in items {
            match item {
                QuotientProgramItem::Identity(identity) => {
                    let before_profile =
                        quotient_shape_profile_enabled().then(|| builder.profile.clone());
                    let expr = Self::quotient_identity_expr(identity);
                    builder.identity_expr(
                        &expr,
                        identity.target,
                        selector_fold.gap_for(identity),
                        cse.as_mut(),
                    );
                    if let Some(before_profile) = before_profile {
                        Self::print_identity_shape_profile(
                            identity,
                            &before_profile,
                            &builder.profile,
                        );
                    }
                }
                QuotientProgramItem::NativePermutation => builder.native_permutation(),
                QuotientProgramItem::NativeLookup => builder.native_lookup(),
                QuotientProgramItem::NativeIdentity(native_idx) => {
                    builder.native_identity(*native_idx);
                }
            }
        }

        builder.finish(quotient_program_encoding())
    }

    fn print_identity_shape_profile(
        identity: &QuotientIdentity,
        before: &QuotientShapeProfile,
        after: &QuotientShapeProfile,
    ) {
        let modarith7 = after.modarith7.saturating_sub(before.modarith7);
        let lin7 = after.lin7.saturating_sub(before.lin7);
        let bilin7_row = after.bilin7_row.saturating_sub(before.bilin7_row);
        let bilin7_pairwise = after.bilin7_pairwise.saturating_sub(before.bilin7_pairwise);
        let pow5 = after.pow5.saturating_sub(before.pow5);
        let fallback_vm_ops = after.fallback_vm_ops.saturating_sub(before.fallback_vm_ops);
        eprintln!(
            "quotient identity shape profile: idx={} source={} modarith7={} lin7={} bilin7_row={} bilin7_pairwise={} pow5={} fallback_vm_ops={}",
            identity.meta.global_index,
            Self::quotient_identity_source_label(&identity.meta.source),
            modarith7,
            lin7,
            bilin7_row,
            bilin7_pairwise,
            pow5,
            fallback_vm_ops,
        );
    }

    fn quotient_identity_source_label(source: &QuotientIdentitySource) -> String {
        match source {
            QuotientIdentitySource::Gate {
                gate_index,
                gate_name,
                constraint_index,
                constraint_name,
                ..
            } => format!(
                "gate[{gate_index}]/{gate_name}/constraint[{constraint_index}]/{constraint_name}"
            ),
            QuotientIdentitySource::Permutation { identity_index } => {
                format!("permutation[{identity_index}]")
            }
            QuotientIdentitySource::Lookup {
                identity_index,
                lookup_index,
                ..
            } => format!("lookup[{lookup_index}]/identity[{identity_index}]"),
            QuotientIdentitySource::Trash {
                trash_index,
                trash_name,
            } => {
                format!("trash[{trash_index}]/{trash_name}")
            }
        }
    }

    /// Repack a midnight-proofs proof from the on-the-wire compressed
    /// form (each G1 = 48 bytes ZCash compressed) into the EIP-2537
    /// padded form (each G1 = 4 × 32-byte BE words) and rewrites scalar
    /// proof elements from midnight-proofs' canonical LE bytes into
    /// canonical BE calldata words. This is the Solidity-facing proof
    /// shim; the native proof bytes remain unchanged.
    ///
    /// This is the off-chain repack step the verifier expects: the
    /// EVM does **not** run the modexp-based BLS12-381 decompression
    /// at every G1 site (which would cost ~80 kg / commitment); the
    /// caller pays that cost off-chain once.
    ///
    /// The walk is driven entirely by the bound `&self.vk` /
    /// `&self.meta` (so it correctly handles the non-trivial proof
    /// shapes the codegen produces: per-phase advices, lookup
    /// multiplicities + chunked helpers + accumulators, perm Z
    /// products, trashcans, quotient limbs, eval block, dummy evals
    /// from `outer-fewer-point-sets`, f_com, q_evals per point set, pi).
    ///
    /// # Panics
    /// - Panics if any G1 in the input fails to decompress (off-curve
    ///   / bad subgroup / malformed compressed encoding).
    /// - Panics if `compressed` is shorter than the schema requires.
    pub fn repack_compressed_proof(&self, compressed: &[u8]) -> Vec<u8> {
        use group::prime::PrimeCurveAffine;
        use group::GroupEncoding;

        let plan = self.repacked_proof_layout_plan();
        let prefix_g1_count = plan.prefix_g1_count();
        let expected_compressed_len = plan.compressed_len();
        assert_eq!(
            compressed.len(),
            expected_compressed_len,
            "compressed proof length mismatch: expected {expected_compressed_len} bytes (prefix_g1={prefix_g1_count}, num_evals={}, num_point_sets={}, +f_com+pi), got {}",
            plan.num_evals,
            plan.num_point_sets,
            compressed.len()
        );

        let mut out: Vec<u8> = Vec::with_capacity(plan.repacked_len());
        let mut cursor = 0usize;
        let push_g1 = |cursor: &mut usize, out: &mut Vec<u8>| {
            let mut comp = <G1Affine as GroupEncoding>::Repr::default();
            comp.as_mut()
                .copy_from_slice(&compressed[*cursor..*cursor + layout::G1_COMPRESSED_BYTES]);
            let cur = *cursor;
            *cursor += layout::G1_COMPRESSED_BYTES;
            let pt: G1Affine = Option::from(<G1Affine as GroupEncoding>::from_bytes(&comp))
                .unwrap_or_else(|| {
                    panic!(
                        "decompress failed at compressed[{cur}..{}]: bytes = 0x{}",
                        cur + layout::G1_COMPRESSED_BYTES,
                        hex::encode(comp.as_ref())
                    )
                });
            if bool::from(pt.is_identity()) {
                out.extend_from_slice(&[0u8; 128]);
                return;
            }
            let x_be = pt.x().to_bytes_be();
            let y_be = pt.y().to_bytes_be();
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&x_be[0..16]);
            out.extend_from_slice(&x_be[16..48]);
            out.extend_from_slice(&[0u8; 16]);
            out.extend_from_slice(&y_be[0..16]);
            out.extend_from_slice(&y_be[16..48]);
        };
        let push_scalar_be = |cursor: &mut usize, out: &mut Vec<u8>| {
            out.extend_from_slice(&scalar_le_to_be_word(
                &compressed[*cursor..*cursor + layout::WORD_BYTES],
            ));
            *cursor += layout::WORD_BYTES;
        };
        for &n in &plan.g1_groups {
            for _ in 0..n {
                push_g1(&mut cursor, &mut out);
            }
        }
        // evals (Fr 32-byte LE in native proof) -> BE calldata words
        // (incl. dummy slots).
        for _ in 0..plan.num_evals {
            push_scalar_be(&mut cursor, &mut out);
        }
        // f_com
        push_g1(&mut cursor, &mut out);
        // q_evals (Fr 32-byte LE in native proof) -> BE calldata words.
        for _ in 0..plan.num_point_sets {
            push_scalar_be(&mut cursor, &mut out);
        }
        // pi
        push_g1(&mut cursor, &mut out);
        assert_eq!(
            cursor,
            compressed.len(),
            "compressed proof not fully consumed"
        );
        out
    }

    #[cfg(test)]
    #[allow(dead_code)]
    pub(crate) fn repacked_proof_scalar_layout_for_test(&self) -> RepackedProofScalarLayout {
        self.repacked_proof_layout_plan().scalar_layout()
    }

    /// Return the compressed/repacked proof layout used by the off-chain shim.
    fn repacked_proof_layout_plan(&self) -> RepackedProofLayoutPlan {
        let proof_cptr = Ptr::calldata(layout::abi::VERIFY_PROOF_PROOF_CPTR);
        let vk = self.generate_vk();
        let (_, meta, _data, _) = self.meta_data_for_stable_static_layout(&vk, proof_cptr);
        let proof_layout = ProofCalldataLayout::from_protocol(
            &meta.protocol,
            layout::abi::VERIFY_PROOF_PROOF_CPTR,
            meta.num_evals,
            meta.num_point_sets,
        );

        RepackedProofLayoutPlan::from_proof_layout(&proof_layout)
    }

    /// Low-memory working-set size that must stay below `VK_MPTR`.
    fn static_working_memory_size_for_meta(&self, meta: &ConstraintSystemMeta) -> usize {
        let pcs_computation = pcs::static_working_memory_size();
        let transcript_words =
            Self::transcript_buffer_layout_for_meta(meta, self.num_instances).words;
        let transcript_end = layout::TRANSCRIPT_BUFFER_START + transcript_words * WORD_BYTES;
        let pcs_end = layout::PCS_PAIRING_SCRATCH_START + pcs_computation * WORD_BYTES;
        let final_pairing_end =
            layout::FINAL_PAIRING_SCRATCH_START + layout::PAIRING_STATIC_WORKING_WORDS * WORD_BYTES;
        let modexp_end = layout::LOW_MEMORY_SCRATCH_START
            + layout::MODEXP_DECOMPRESSION_WORKING_WORDS * WORD_BYTES;
        let verifier_return_end = layout::VERIFIER_RETURN_BUFFER_START + WORD_BYTES;
        let quotient_return_end =
            layout::QUOTIENT_RETURN_BUFFER_START + (2 + meta.num_simple_selectors) * WORD_BYTES;

        itertools::max([
            // Transcript buffer (streaming Keccak256). The buffer must
            // fit *below* `VK_MPTR` because every `mload(VK_MPTR + ...)`
            // assumes the VK contract bytes copied via `extcodecopy`
            // remain intact, and the buffer would otherwise overwrite
            // them as it grows past the start of the VK area.
            transcript_end,
            // PCS computation scratch
            pcs_end,
            // Pairing: two-pair input frame plus output word, rooted above
            // Solidity's reserved memory prefix.
            final_pairing_end,
            // Modexp scratch for decompression (240 bytes input + 48
            // bytes output = 9 words; we round up to 16 to leave room
            // for separate scratch areas).
            modexp_end,
            // Low-memory return frames. The quotient evaluator's output grows
            // with the number of simple selector buckets.
            verifier_return_end,
            quotient_return_end,
        ])
        .unwrap()
    }

    #[cfg(test)]
    /// Test helper exposing the transcript buffer word bound.
    pub(super) fn transcript_buffer_words_bound(
        meta: &ConstraintSystemMeta,
        num_instances: usize,
    ) -> usize {
        Self::transcript_buffer_layout_for_meta(meta, num_instances).words
    }

    /// Compute the transcript buffer layout for a metadata snapshot.
    pub(super) fn transcript_buffer_layout_for_meta(
        meta: &ConstraintSystemMeta,
        num_instances: usize,
    ) -> TranscriptBufferLayout {
        // The Step 6 transcript model is a streaming Keccak256 buffer rooted
        // at TRANSCRIPT_BUFFER_START. The buffer monotonically grows between
        // two challenge squeezes and is reset to one seed word after each
        // squeeze. This function returns the number of words needed above
        // that root; the caller adds the 0x80 base when choosing VK_MPTR. For
        // midnight-proofs verifiers the dominating run is whichever of the
        // following is largest:
        //   (a) initial absorbs (vk_digest + committed_pi + num_instances
        //       + all instance scalars + all phase-1 advices) before the
        //       first user-phase challenge squeeze (`theta`), or
        //   (b) the evaluation block (all `num_evals` scalars) absorbed
        //       after the `y` squeeze and before the next squeeze.
        //
        // We compute a per-run conservative upper bound for each and
        // take the max, then add the 32-byte post-squeeze seed cushion.
        //
        // Per-absorb costs in the patched (uncompressed-G1) emitter:
        //   - word                         = 32 bytes  (`common_word`)
        //   - uncompressed G1              = 128 bytes (`common_uncompressed_g1`)
        //   - squeeze output               = 32 bytes  (post-squeeze seed)
        // The earlier (compressed-G1) emitter used 49 bytes per G1; the
        // 49 used here is wrong now that the verifier hashes the 128-byte
        // EIP-2537 padded form, so we use 128. Mismatching the bound
        // causes the keccak buffer to overrun `VK_MPTR` mid-verify and
        // silently corrupt `K_MPTR`, `OMEGA_MPTR`, etc., producing a
        // multi-billion-gas spin in the Lagrange block.
        let proof_layout = ProofCalldataLayout::from_protocol(
            &meta.protocol,
            0,
            meta.num_evals,
            meta.num_point_sets,
        );
        TranscriptBufferLayout::from_proof_layout(&proof_layout, num_instances)
    }
}
