"""Headless API for d810-ng deobfuscation.

Public functions:
    configure()  — Load a project configuration (which rules to use)
    start()      — Install Hex-Rays deobfuscation hooks
    stop()       — Remove hooks, stop deobfuscation
    status()     — Query current state

Usage from IDAPython (headless idat64 or ida-hub):

    from d810.headless import start, stop, configure

    # Option 1: use built-in config by name
    configure(project="default_unflattening_ollvm.json")
    start()

    # Now decompile — deobfuscation runs automatically
    import ida_hexrays
    cfunc = ida_hexrays.decompile(some_ea)

    # Option 2: specify custom config dir
    configure(config_dir="/path/to/cfg/d810", project="my_rules.json")
    start()

    # Stop deobfuscation
    stop()

Built-in projects for common obfuscators:
    - default_unflattening_ollvm.json    — OLLVM CFF + MBA
    - default_unflattening_switch_case.json — switch-case flattening
    - default_unflattening_approov.json  — Approov-style
    - default_instruction_only.json      — MBA only (no CFG)
    - example_libobfuscated.json         — generic libobfuscated
    - hodur_deobfuscation.json           — Hodur obfuscator
    - eidolon.json                       — Eidolon obfuscator

ida-hub integration example:

    import sys
    sys.path.insert(0, "/path/to/d810-ng/src")
    from d810.headless import start, stop, configure, status

    configure(project="default_unflattening_ollvm.json")
    start()

    s = status()
    print(f"project={s['project']}, rules={s['ins_rules']}")

    import idautils, ida_hexrays
    for ea in idautils.Functions():
        cfunc = ida_hexrays.decompile(ea)
        print(str(cfunc))

    stop()
"""
from __future__ import annotations

import pathlib
from typing import Any

from d810.core.logging import getLogger
from d810.core.singleton import SingletonMeta

logger = getLogger("D810.headless")

# Module-level state
_state: Any | None = None
_configured: bool = False


def _ensure_optimizer_registrations() -> None:
    """Import all optimizer handler modules to trigger __init_subclass__ registration.

    In GUI mode, ida_reloader's walk_packages() imports every sub-module of
    the d810 package, which triggers class registration as a side effect.
    Headless mode skips the reloader, so we import the handlers explicitly.
    """
    # Instruction optimizers
    from d810.optimizers.microcode.instructions.chain import handler as _chain  # noqa: F401
    from d810.optimizers.microcode.instructions.early import handler as _early  # noqa: F401
    from d810.optimizers.microcode.instructions.peephole import handler as _peephole  # noqa: F401
    from d810.optimizers.microcode.instructions.z3 import handler as _z3  # noqa: F401
    from d810.optimizers.microcode.instructions.pattern_matching import handler as _pat  # noqa: F401
    from d810.optimizers.microcode.instructions.analysis import handler as _analysis  # noqa: F401
    try:
        from d810.optimizers.microcode.instructions.egraph import handler as _egraph  # noqa: F401
    except ImportError:
        pass

    # Chain rules depend on ChainSimplificationRule from handler
    from d810.optimizers.microcode.instructions.chain import chain_rules as _chainrules  # noqa: F401

    # Flow rules are auto-imported by flow/__init__.py when ida_hexrays is available
    from d810.optimizers.microcode.flow import handler as _flow  # noqa: F401

    # Experimental rules
    try:
        from d810.optimizers.microcode.instructions.pattern_matching import experimental as _exp  # noqa: F401
    except ImportError:
        pass

    # VerifiableRules (DSL-based MBA rules)
    try:
        from d810.mba.rules import _base as _mba_base  # noqa: F401
    except ImportError:
        pass


def _ensure_hexrays() -> bool:
    """Check that Hex-Rays decompiler is available and initialized."""
    try:
        import ida_hexrays
        return ida_hexrays.init_hexrays_plugin()
    except ImportError:
        return False


def configure(
    *,
    project: str | None = None,
    config_dir: str | pathlib.Path | None = None,
    ida_user_dir: str | pathlib.Path | None = None,
) -> None:
    """Load a project configuration for headless deobfuscation.

    Args:
        project: Name of project JSON file (e.g. "default_unflattening_ollvm.json").
                 If None, loads the project at last_project_index from options.json.
        config_dir: Directory containing options.json and project JSONs.
                    Defaults to ~/.idapro/cfg/d810/ or built-in conf/.
        ida_user_dir: IDA user directory (default ~/.idapro).
    """
    global _state, _configured

    from d810.core.config import D810Configuration
    from d810.manager import D810State

    # Ensure all optimizer handler modules are imported so their
    # __init_subclass__ registrations fire. In GUI mode, the
    # ida_reloader's walk_packages() does this; in headless we
    # must do it explicitly.
    _ensure_optimizer_registrations()

    # Reset singleton to get fresh state
    SingletonMeta._instances.pop("D810State", None)

    # Build config with optional overrides
    config_kwargs: dict[str, Any] = {}
    if ida_user_dir is not None:
        config_kwargs["ida_user_dir"] = str(ida_user_dir)
    if config_dir is not None:
        config_path = pathlib.Path(config_dir) / "options.json"
        config_kwargs["config_path"] = str(config_path)

    d810_config = D810Configuration(**config_kwargs)

    # Create fresh state and load with our config
    state = D810State()
    state.load(gui=False, d810_config=d810_config)

    # Resolve target project
    projects = state.project_manager.project_names()
    if not projects:
        raise ValueError(
            "No project configurations found. "
            "Place .json files in the config directory or specify config_dir."
        )

    if project is not None:
        if project not in projects:
            raise ValueError(
                f"Project '{project}' not found. "
                f"Available: {', '.join(projects)}"
            )
        target_index = state.project_manager.index(project)
    else:
        raw_index = d810_config.get("last_project_index", 0)
        try:
            target_index = int(raw_index)
        except (TypeError, ValueError):
            target_index = 0
        target_index = max(0, min(target_index, len(projects) - 1))

    # Switch to requested project if different from default
    if target_index != 0:
        state.load_project(target_index)

    # Register in singleton
    SingletonMeta._instances["D810State"] = state

    _state = state
    _configured = True
    logger.info(
        "Headless configured: project=%s, ins_rules=%d, blk_rules=%d",
        state.current_project.path.name if state.current_project else "?",
        len(state.current_ins_rules),
        len(state.current_blk_rules),
    )


def start() -> None:
    """Start deobfuscation — install Hex-Rays microcode hooks.

    Must call configure() first. After start(), any call to
    ida_hexrays.decompile() will trigger d810-ng optimization rules.

    Raises:
        RuntimeError: If not configured or Hex-Rays unavailable.
    """
    global _state, _configured

    if not _configured or _state is None:
        raise RuntimeError(
            "d810-ng not configured. Call configure() first."
        )

    if _state.manager.started:
        logger.info("d810-ng already started — idempotent, no-op.")
        return

    if not _ensure_hexrays():
        raise RuntimeError(
            "Hex-Rays decompiler not available. "
            "Ensure IDA has Hex-Rays loaded."
        )

    _state.start_d810()
    logger.info("d810-ng headless started.")


def stop() -> None:
    """Stop deobfuscation — remove Hex-Rays hooks."""
    global _state

    if _state is None:
        return

    if _state.manager.started:
        _state.stop_d810()
        logger.info("d810-ng headless stopped.")


def status() -> dict[str, Any]:
    """Query current headless deobfuscation state.

    Returns:
        Dict with keys:
            started (bool): Whether hooks are installed
            configured (bool): Whether configure() has been called
            project (str|None): Loaded project name
            ins_rules (int): Number of active instruction rules
            blk_rules (int): Number of active block rules
    """
    result: dict[str, Any] = {
        "started": False,
        "configured": _configured,
        "project": None,
        "ins_rules": 0,
        "blk_rules": 0,
    }

    if _state is not None:
        result["started"] = _state.manager.started
        if _state.current_project is not None:
            result["project"] = _state.current_project.path.name
        result["ins_rules"] = len(_state.current_ins_rules)
        result["blk_rules"] = len(_state.current_blk_rules)

    return result
