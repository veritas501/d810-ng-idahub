"""Regression: rejecting conditional fallthrough must precede any CFG copies.

Run inside IDA with a function containing a conditional jump loaded. The
JNI_OnLoad table/CC experiment is selected through D810_DUPLICATION_TEST_EA.
No IDA objects are mocked: only history grouping is controlled to isolate the
mutation boundary in try_to_duplicate_one_block().
"""
import os
from types import SimpleNamespace

import pytest
import ida_funcs
import ida_hexrays
import idautils

from d810.hexrays import tracker
from d810.hexrays.cfg_utils import duplicate_block

pytestmark = [pytest.mark.requires_ida, pytest.mark.runtime]


def conditional_mba():
    requested = os.environ.get("D810_DUPLICATION_TEST_EA")
    entries = [int(requested, 0)] if requested else list(idautils.Functions())
    for ea in entries:
        func = ida_funcs.get_func(ea)
        if func is None:
            continue
        failure = ida_hexrays.hexrays_failure_t()
        mba = ida_hexrays.gen_microcode(
            ida_hexrays.mba_ranges_t(func), failure, None,
            ida_hexrays.DECOMP_NO_WAIT, ida_hexrays.MMAT_LOCOPT,
        )
        if mba is None:
            continue
        for i in range(mba.qty):
            pred = mba.get_mblock(i)
            if (pred.tail is not None and pred.nsucc() == 2
                    and ida_hexrays.is_mcode_jcond(pred.tail.opcode)):
                fall = mba.get_mblock(pred.serial + 1)
                if fall.serial != pred.tail.d.b and fall.serial in list(pred.succset):
                    return mba, pred, fall
    pytest.skip("No conditional fallthrough in loaded database")


def graph_snapshot(mba):
    return [
        (b.serial, tuple(b.predset), tuple(b.succset),
         b.tail.dstr() if b.tail is not None else None)
        for b in (mba.get_mblock(i) for i in range(mba.qty))
    ]


@pytest.mark.parametrize("valid_group_before_fallthrough", [False, True])
def test_fallthrough_rejection_is_atomic(monkeypatch, valid_group_before_fallthrough):
    mba, pred, fall = conditional_mba()
    history = SimpleNamespace(
        block_path=[pred, fall], block_serial_path=[pred.serial, fall.serial]
    )
    # First group is retained. An unsupported later group must reject the
    # entire round, even if an earlier group could have been copied.
    groups = {-1: [history]}
    if valid_group_before_fallthrough:
        valid = next((mba.get_mblock(i) for i in range(mba.qty)
                      if mba.get_mblock(i).nsucc() == 1
                      and (mba.get_mblock(i).tail is None or not
                           ida_hexrays.is_mcode_jcond(mba.get_mblock(i).tail.opcode))), None)
        if valid is None:
            pytest.skip("No one-way predecessor available")
        groups[valid.serial] = [history]
    groups[pred.serial] = [history]
    monkeypatch.setattr(tracker, "get_block_with_multiple_predecessors",
                        lambda histories: (fall, groups))

    def must_not_copy(*args, **kwargs):
        pytest.fail("copy_block reached before fallthrough preflight")

    monkeypatch.setattr(tracker, "duplicate_block", must_not_copy)
    before = graph_snapshot(mba)
    path = list(history.block_path)
    assert tracker.try_to_duplicate_one_block([history]) == (0, 0)
    assert graph_snapshot(mba) == before
    assert history.block_path == path
    mba.verify(True)


def test_conditional_copy_has_adjacent_unique_fallthrough():
    mba, original, fall = conditional_mba()
    taken = mba.get_mblock(original.tail.d.b)
    original_succs = list(original.succset)
    original_eas = []
    ins = original.head
    while ins is not None:
        original_eas.append(ins.ea)
        ins = ins.next

    copied, bridge = duplicate_block(original, verify=False)
    assert bridge is not None
    assert copied.nextb.serial == bridge.serial
    assert copied.tail.d.b == taken.serial
    assert copied.nsucc() == 2
    assert set(copied.succset) == {taken.serial, bridge.serial}
    assert list(bridge.succset) == [fall.serial]
    assert list(bridge.predset) == [copied.serial]
    assert list(original.succset) == original_succs
    assert copied.serial not in original.predset
    ins = copied.head
    while ins is not None:
        assert ins.ea not in original_eas
        ins = ins.next
    mba.verify(True)
