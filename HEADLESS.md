# d810-ng Headless Mode

Script-driven deobfuscation without IDA GUI. For use with `idat64`, ida-hub, or any IDAPython automation.

## Installation

d810-ng must be installed into IDA Pro's Python environment.

```bash
# Locate IDA's bundled Python
IDA_PYTHON=~/ida-pro-9.3/python_standalone/bin/python3

# Install d810-ng (editable, so code changes take effect immediately)
$IDA_PYTHON -m pip install -e /path/to/d810-ng

# Install z3 (required for MBA constraint solving)
$IDA_PYTHON -m pip install z3-solver

# Verify
$IDA_PYTHON -c "from d810.headless import start, stop, configure, status; print('OK')"
```

For ida-hub or other agents: replace paths with your actual IDA install location and d810-ng source path.

## API Reference

Four functions. Import directly:

```python
from d810.headless import start, stop, configure, status
```

### `configure(*, project=None, config_dir=None, ida_user_dir=None)`

Load a project configuration. Must be called before `start()`.

| Parameter | Type | Description |
|-----------|------|-------------|
| `project` | `str \| None` | Project JSON filename (e.g. `"default_unflattening_ollvm.json"`). If `None`, loads the default project from `options.json`. |
| `config_dir` | `str \| Path \| None` | Directory containing `options.json` and project JSONs. Defaults to `~/.idapro/cfg/d810/` or the built-in `conf/` directory. |
| `ida_user_dir` | `str \| Path \| None` | IDA user directory. Defaults to `~/.idapro`. |

### `start()`

Install Hex-Rays microcode optimization hooks. After this call, every `ida_hexrays.decompile()` triggers d810-ng deobfuscation rules automatically.

Raises `RuntimeError` if not configured or Hex-Rays unavailable.

### `stop()`

Remove optimization hooks. Decompile calls after this return raw (un-deobfuscated) output.

### `status() -> dict`

Query current state. Returns:

```python
{
    "started": bool,      # hooks installed
    "configured": bool,    # configure() called
    "project": str|None,   # loaded project name
    "ins_rules": int,      # active instruction rules
    "blk_rules": int,      # active block rules
}
```

## Built-in Projects

| Project | ins_rules | blk_rules | Purpose |
|---------|-----------|-----------|---------|
| `default_unflattening_ollvm.json` | 177 | 4 | OLLVM control flow flattening + MBA |
| `default_unflattening_switch_case.json` | ~170 | 4 | Switch-case flattening |
| `default_unflattening_approov.json` | ~170 | 4 | Approov-style obfuscation |
| `default_instruction_only.json` | ~170 | 0 | MBA simplification only (no CFG) |
| `example_libobfuscated.json` | ~170 | 4 | Generic libobfuscated |
| `hodur_deobfuscation.json` | ~170 | 4 | Hodur obfuscator |
| `eidolon.json` | ~170 | 4 | Eidolon obfuscator |

## Usage: Start Deobfuscation

Run this IDAPython script to enable deobfuscation. After `start()`, all decompilation calls are automatically optimized.

```python
from d810.headless import configure, start, status

# Load OLLVM deobfuscation rules
configure(project="default_unflattening_ollvm.json")

# Install hooks — decompile() now auto-deobfuscates
start()

# Verify
s = status()
print(f"d810-ng started: project={s['project']}, "
      f"ins_rules={s['ins_rules']}, blk_rules={s['blk_rules']}")

# Decompile a function — deobfuscation happens transparently
import ida_hexrays
cfunc = ida_hexrays.decompile(0x401000)
print(str(cfunc))
```

## Usage: Stop Deobfuscation

Run this IDAPython script to disable deobfuscation. After `stop()`, decompilation returns raw output.

```python
from d810.headless import stop, status

# Remove hooks — decompile() returns raw output again
stop()

# Verify
s = status()
print(f"d810-ng stopped: started={s['started']}")
```

## ida-hub Integration

Send these scripts to ida-hub via its execute API.

**Start** (send as script content to ida-hub):

```python
import sys
sys.path.insert(0, "/path/to/d810-ng/src")

from d810.headless import configure, start, status

configure(project="default_unflattening_ollvm.json")
start()

s = status()
print(f"d810-ng: project={s['project']}, ins_rules={s['ins_rules']}, blk_rules={s['blk_rules']}")
```

**Stop** (send as script content to ida-hub):

```python
from d810.headless import stop, status

stop()
s = status()
print(f"d810-ng: started={s['started']}")
```

**Batch decompile a range** (start + decompile + stop in one script):

```python
import sys
sys.path.insert(0, "/path/to/d810-ng/src")

from d810.headless import start, stop, configure

configure(project="default_unflattening_ollvm.json")
start()

import idautils
import ida_hexrays

results = []
for func_ea in idautils.Functions(0x401000, 0x402000):
    try:
        cfunc = ida_hexrays.decompile(func_ea)
        results.append({"ea": hex(func_ea), "pseudocode": str(cfunc)})
    except Exception as e:
        results.append({"ea": hex(func_ea), "error": str(e)})

stop()
print(f"Decompiled {len(results)} functions")
for r in results:
    if "error" in r:
        print(f"  {r['ea']}: ERROR {r['error']}")
    else:
        print(f"  {r['ea']}: {len(r['pseudocode'])} chars")
```

## Custom Configuration

Point to a custom config directory with your own rule JSONs:

```python
from d810.headless import configure, start

configure(
    config_dir="/home/user/my_d810_configs",
    project="my_custom_rules.json"
)
start()
```

## GUI Mode

Headless mode does not affect the GUI plugin. Press `Ctrl-Shift-D` in IDA to start deobfuscation via the traditional UI. The `D810_HEADLESS=1` environment variable only guards the version check in the plugin init path.
