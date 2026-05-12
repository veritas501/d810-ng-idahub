__version__ = "0.6.6"

try:
    from d810.speedups.bootstrap import ensure_speedups_on_path

    ensure_speedups_on_path()
except Exception:
    # Keep package import robust even if environment setup is incomplete.
    pass


def get_headless_api():
    """Access the headless API module.

    Usage:
        api = d810.get_headless_api()
        api.configure(project="default_unflattening_ollvm.json")
        api.start()

    Or import directly:
        from d810.headless import start, stop, configure, status
    """
    from d810 import headless as _headless
    return _headless
