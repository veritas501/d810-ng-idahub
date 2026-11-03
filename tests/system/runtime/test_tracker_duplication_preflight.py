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
from d810.hexrays.deferred_modifier import DeferredGraphModifier
from d810.optimizers.microcode.flow.flattening import generic

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


@pytest.mark.parametrize("raises", [False, True])
def test_stale_precondition_skips_without_aborting_batch(raises):
    mba, _, _ = conditional_mba()
    sources = [mba.get_mblock(i) for i in range(mba.qty)
               if mba.get_mblock(i).nsucc() == 1][:2]
    assert len(sources) == 2
    modifier = DeferredGraphModifier(mba)
    first, second = sources
    modifier.queue_goto_change(first.serial, first.succset[0])
    modifier.queue_goto_change(second.serial, second.succset[0])
    calls = []

    def stale():
        calls.append("stale")
        if raises:
            raise RuntimeError("state cannot be recovered")
        return False

    def valid():
        calls.append("valid")
        return True

    modifier.modifications[0].precondition = stale
    modifier.modifications[1].precondition = valid
    before = graph_snapshot(mba)[first.serial]
    assert modifier.apply(run_optimize_local=False, run_deep_cleaning=False,
                          defer_post_apply_maintenance=True) == 1
    assert calls == ["stale", "valid"]
    assert graph_snapshot(mba)[first.serial] == before
    assert not modifier.verify_failed
    mba.verify(True)


@pytest.mark.parametrize("current", [[], [[None]], [[2]], [[1], [2]]])
def test_dispatcher_proof_rechecks_current_histories(monkeypatch, current):
    mba, _, _ = conditional_mba()
    father = next(mba.get_mblock(i) for i in range(mba.qty)
                  if mba.get_mblock(i).nsucc() == 1)
    values = [[1]]
    queried = []
    info = SimpleNamespace(entry_block=SimpleNamespace(use_before_def_list=[]))

    def histories(*args):
        queried.append(True)
        return [object()]

    producer = SimpleNamespace(mba=mba, get_dispatcher_father_histories=histories,
                               check_if_histories_are_resolved=lambda _: True)
    monkeypatch.setattr(generic, "get_all_possibles_values", lambda *a, **kw: values)
    proof = generic.GenericDispatcherUnflatteningRule._make_dispatcher_precondition(
        producer, father, info, [1]
    )
    assert proof()
    values = current
    assert not proof()
    assert len(queried) == 2


def test_jni_onload_default_unflattening():
    """Requires the table/CC JNI_OnLoad IDB; never substitute a null stub."""
    requested = os.environ.get("D810_JNI_ONLOAD_TEST_EA")
    if not requested:
        pytest.skip("Set D810_JNI_ONLOAD_TEST_EA with the table/CC IDB loaded")
    from d810.manager import D810State

    state = D810State()
    state.stop_d810()
    state.load_project(state.project_manager.index("default_unflattening_ollvm.json"))
    rule = next(r for r in state.current_blk_rules if r.name == "Unflattener")
    assert rule.max_duplication_passes == 20
    assert rule.config["min_dispatcher_internal_block"] == 1
    assert rule.config["min_dispatcher_exit_block"] == 2
    assert rule.config["min_dispatcher_comparison_value"] == 1
    state.start_d810()
    try:
        for _ in range(2):
            failure = ida_hexrays.hexrays_failure_t()
            cf = ida_hexrays.decompile(int(requested, 0), failure,
                                      ida_hexrays.DECOMP_NO_CACHE)
            assert cf is not None, failure.str
            text = str(cf)
            assert "GetEnv" in text
            assert "return -1;" in text and "return 65540;" in text
            assert "for (" not in text and "while (" not in text
            assert "return (int)vm" not in text and "JUMPOUT" not in text
    finally:
        state.stop_d810()
