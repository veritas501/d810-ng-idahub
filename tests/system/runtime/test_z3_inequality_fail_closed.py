"""Unknown operands must not become proofs of universal inequality.

Regression for IDA 9.5 canary comparisons: translating two mops yielded one
expression, and Z3setzRuleGeneric incorrectly removed the normal return path.
"""
import pytest
import ida_hexrays
import z3

from d810.expr import z3_utils as zu

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime]


def number(value):
    mop = ida_hexrays.mop_t()
    mop.make_number(value, 4)
    return mop


@pytest.fixture(autouse=True)
def clear_proofs():
    zu._Z3_NEQ_CACHE.clear()
    yield
    zu._Z3_NEQ_CACHE.clear()


@pytest.mark.parametrize("invalid", [None, object()])
@pytest.mark.parametrize("reverse", [False, True])
def test_missing_operand_is_not_unequal(invalid, reverse):
    args = (number(0), invalid) if reverse else (invalid, number(0))
    assert zu.z3_check_mop_inequality(*args) is False


@pytest.mark.parametrize("count", [0, 1])
def test_incomplete_translation_does_not_claim_or_cache_proof(monkeypatch, count):
    a, b = number(0), number(1)
    expressions = [z3.BitVecVal(0, 32), z3.BitVecVal(1, 32)]
    monkeypatch.setattr(zu, "mop_list_to_z3_expression_list",
                        lambda _: expressions[:count])
    assert zu.z3_check_mop_inequality(a, b) is False
    assert not zu._Z3_NEQ_CACHE
    # A later complete translation must still be able to prove inequality.
    monkeypatch.setattr(zu, "mop_list_to_z3_expression_list", lambda _: expressions)
    assert zu.z3_check_mop_inequality(a, b, solver=z3.Solver()) is True


def test_complete_proofs_and_unknown_register():
    assert not zu.z3_check_mop_inequality(number(0), number(0), solver=z3.Solver())
    assert zu.z3_check_mop_inequality(number(0), number(1), solver=z3.Solver())
    reg = ida_hexrays.mop_t()
    reg.make_reg(0, 4)
    assert not zu.z3_check_mop_inequality(reg, number(0), solver=z3.Solver())
