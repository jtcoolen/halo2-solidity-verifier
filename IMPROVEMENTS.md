# Improvements

Yes. We can borrow the architecture, not assume the audit transfers to us.
Axiom's README says `snark-verifier` v0.1.1+ completed Trail of Bits audits,
but our generated BLS12-381/Midnight assembly would still need its own review
surface.

The best ideas to take:

1. **Typed verifier pipeline**
   `snark-verifier` separates proof-system semantics from backend lowering with
   generic `Loader`, `ScalarLoader`, and `EcPointLoader` traits. Same verifier
   logic can target native, Halo2, or EVM backends. This is much safer than
   hand-emitting Yul from proof-system code.

2. **Protocol AST before assembly**
   It compiles Halo2 into a `PlonkProtocol` with an expression AST like
   `Expression::{Constant, Polynomial, Challenge, Sum, Product, Scaled,
   DistributePowers}`. The quotient is represented as structured data, not
   strings.

3. **Centralized lowering**
   The EVM backend has a small scalar AST,
   `Value::{Constant, Memory, Negated, Sum, Product}`, then one lowering path
   decides how to emit Yul/compact IR. That gives one place to audit arithmetic
   emission.

4. **Expression cache / CSE**
   Their `EvmLoader::scalar` caches expression identifiers to memory slots. We
   already adopted the quotient version with global VM CSE.

5. **Explicit sum/sum-product helpers**
   Their `ScalarLoader` has `sum_with_coeff_and_const` and
   `sum_products_with_coeff_and_const`. We just added the quotient-side version,
   which saved ~7.4k gas.

6. **Typed compact IR**
   Their compact backend lowers into enum instructions like `ScalarAdd`,
   `ScalarMul`, `ScalarMulAdd...`, calldata loads, point loads, staticcalls,
   etc. That is much safer than free-form Yul snippets.

## What I Would Apply Here

The biggest safety win is replacing our "emit Yul strings, then parse them back
into quotient expressions" path with a typed quotient IR:

```text
Midnight/Halo2 constraints
  -> QuotientExpr AST
  -> normalization passes
  -> CSE / sum-product folding
  -> checked VM program or checked inline Yul
  -> generated Solidity
```

Then add a verifier for the lowering:

- stack never underflows
- all temp slots initialized before read
- constant/program indices in range
- memory regions do not overlap
- every opcode has fixed semantics
- generated VM/native evaluation match on random environments
- generated Solidity checkpoint values match native verifier values

This would not automatically reduce gas, but it would make the assembly much
more auditable and soundness-oriented. For gas, we still need hybrid inlining or
helper/sharded straight-line evaluators.

Sources: Axiom repo README and audit note, `snark-verifier` docs/source, and
local checkout paths under `/Users/Julien.Coolen/snark-verifier`.
