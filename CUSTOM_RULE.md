# Custom Rule Guide

D-810 ng supports two ways to add custom deobfuscation rules: **DSL rules** for structural pattern matching, and **optinsn_t hooks** for semantic-level transformations. This guide covers both approaches with practical examples.

## Method 1: DSL Rules (VerifiableRule)

Best for patterns where the expression structure in microcode matches your symbolic pattern directly.

### Basic Rule

```python
from d810.mba.dsl import Var, Const
from d810.mba.rules._base import VerifiableRule

x, y = Var("x_0"), Var("x_1")

class MyRule(VerifiableRule):
    maturities = [2, 3, 4, 5]  # MMAT_PREOPTIMIZED through MMAT_GLBOPT1

    PATTERN = ~(~x ^ y)
    REPLACEMENT = x ^ y

    DESCRIPTION = "Simplify ~(~x ^ y) to x ^ y"
    REFERENCE = "NOT distribution over XOR"
```

The DSL supports: `~` (bnot), `-` (neg), `+`, `-`, `*`, `&`, `|`, `^`, and `Const()` for constant matching.

### Rule with Constraints

When the replacement needs a computed constant:

```python
x = Var("x_0")
c = Const("c_1")
bnot_c = Const("bnot_c_1")

class MyCstRule(VerifiableRule):
    maturities = [2, 3, 4, 5]

    PATTERN = ~(x ^ c)
    REPLACEMENT = x ^ bnot_c

    CONSTRAINTS = [bnot_c == ~c]  # bnot_c is computed as ~c at runtime

    DESCRIPTION = "Simplify ~(x ^ c) to x ^ ~c"
```

Constraint types:
- **Defining**: `bnot_c == ~c` — computes a new constant for the replacement
- **Checking**: `bnot_x == ~x` — verifies a structural relationship between matched operands (both must appear in PATTERN)

### Rule with `bnot_x` Verification

When you need to verify that a matched operand is the bitwise NOT of another:

```python
x, y = Var("x_0"), Var("x_1")
bnot_x, bnot_y = Var("bnot_x_0"), Var("bnot_x_1")

class MyFactorRule(VerifiableRule):
    maturities = [2, 3, 4, 5]

    PATTERN = (x & bnot_y) | (bnot_x & y)
    REPLACEMENT = x ^ y

    CONSTRAINTS = [
        bnot_x == ~x,  # structural check: bnot_x must be ~x in microcode
        bnot_y == ~y,
    ]
```

**Important**: Both sides of a checking constraint must be matched from the PATTERN. If `x` only appears in REPLACEMENT but not PATTERN, the constraint will silently fail.

### Adding to Config Files

New rules auto-register via `VerifiableRule.registry`, but must be listed in JSON config files to be activated:

```json
{
    "name": "MyRule",
    "is_activated": true,
    "config": {}
}
```

Add the entry after a similar rule in all relevant config files under `src/d810/conf/`.

### Z3 Verification

Rules without `SKIP_VERIFICATION = True` are automatically verified by Z3. Add a test entry in `tests/unit/mba/test_z3_simplifications.py`:

```python
RuleInfo(
    name="MyRule",
    expr="(~(~(x_0) ^ x_1)) => (x_0 ^ x_1)",
    known_incorrect=False,
    comment=None,
),
```

## Method 2: optinsn_t Hook (Runtime Semantic Matching)

Best for patterns where the microcode structure doesn't match a simple symbolic pattern — e.g., when `~x` is computed through a different path than `x` (via `xdu`, shifts, or truncation).

### Example: MBA AND-Mask Pattern

The expression `((~x & MASK) ^ x) & MASK ^ x` simplifies to `MASK ^ x`, but in microcode `~x` may be structurally different from `x`:

```
# Microcode (actual):
xor (((low.1(bnot(xdu.4(byte6 >> 8))) & 0xE0) ^ byte7) & 0xE0), byte7, dst
# ~x is: low.1(bnot(xdu.4(byte6 >> 8)))
# x is:  byte7 (direct global reference)
# Structurally different — DSL pattern won't match
```

Solution — use `optinsn_t` for semantic matching:

```python
import ida_hexrays

class MbaAndMaskOptimizer(ida_hexrays.optinsn_t):
    def func(self, blk, insn, optflags):
        if insn.opcode != ida_hexrays.m_xor:
            return 0
        if insn.l.t != ida_hexrays.mop_d:
            return 0

        inner = insn.l.d
        if inner.opcode != ida_hexrays.m_and:
            return 0

        # Find mask constant in AND
        if inner.r.t == ida_hexrays.mop_n:
            mask_val = inner.r.nnn.value
            and_other = inner.l
        elif inner.l.t == ida_hexrays.mop_n:
            mask_val = inner.l.nnn.value
            and_other = inner.r
        else:
            return 0

        if and_other.t != ida_hexrays.mop_d:
            return 0
        inner_xor = and_other.d
        if inner_xor.opcode != ida_hexrays.m_xor:
            return 0

        # Check if one side of inner XOR contains bnot
        def has_bnot(ins, depth=0):
            if depth > 6: return False
            if ins.opcode == ida_hexrays.m_bnot: return True
            if ins.l.t == ida_hexrays.mop_d and has_bnot(ins.l.d, depth+1): return True
            if hasattr(ins, 'r') and ins.r.t == ida_hexrays.mop_d:
                if has_bnot(ins.r.d, depth+1): return True
            return False

        if inner_xor.l.t == ida_hexrays.mop_d and has_bnot(inner_xor.l.d):
            x_side = inner_xor.r
        elif inner_xor.r.t == ida_hexrays.mop_d and has_bnot(inner_xor.r.d):
            x_side = inner_xor.l
        else:
            return 0

        # Verify x_side matches outer x operand
        if not x_side.equal_mops(insn.r, ida_hexrays.EQ_IGNSIZE):
            return 0

        # Replace: xor(complex, x, dst) => xor(MASK, x, dst)
        new_l = ida_hexrays.mop_t()
        new_l.make_number(mask_val, insn.r.size)
        insn.l.swap(new_l)
        return 1  # instruction changed
```

### Dynamic Injection via ida-hub

Install at runtime without modifying d810 source or restarting IDA:

```python
# Install (persistent until IDA restart)
import __main__
__main__._my_opt = MbaAndMaskOptimizer()
__main__._my_opt.install()

# Uninstall
__main__._my_opt.remove()
del __main__._my_opt
```

Store in `__main__` to prevent garbage collection. The optimizer fires on every subsequent `F5` decompilation.

### Dynamic Injection via d810 API

Inject a DSL rule into the running d810 optimizer:

```python
from d810.mba.backends.ida import IDAPatternAdapter
from d810.manager import D810State

adapter = IDAPatternAdapter(MyRule())

state = D810State()
state.manager.instruction_optimizer.add_rule(adapter)
```

## When to Use Which

| Criteria | DSL Rule | optinsn_t Hook |
|----------|----------|----------------|
| `~x` and `x` structurally identical in microcode | Yes | Overkill |
| `~x` computed via different path (xdu/shift/low) | Won't match | Yes |
| Need Z3 verification | Yes | No |
| Persistent across sessions | Yes (source + config) | No (runtime only) |
| Quick experiment / one-off | Possible | Easier |
| Cross-instruction patterns (two insns combined) | No | Yes |
