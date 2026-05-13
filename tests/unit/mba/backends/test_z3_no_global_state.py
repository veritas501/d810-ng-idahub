"""Verify d810 never modifies z3 global state."""

import unittest
from unittest.mock import patch

import z3

from d810.mba.backends.z3 import Z3VerificationEngine
from d810.mba.dsl import Var


class TestZ3NoGlobalState(unittest.TestCase):
    """Ensure d810 does not call z3.set_option (process-global side effect)."""

    def test_prove_equivalence_with_timeout_does_not_set_global_option(self):
        """Z3VerificationEngine must use solver-level timeout, not z3.set_option."""
        from d810.mba.verifier import VerificationOptions

        engine = Z3VerificationEngine()
        x, y = Var("x"), Var("y")

        opts = VerificationOptions(timeout_ms=500)

        with patch.object(z3, "set_option", wraps=z3.set_option) as mock_set_option:
            engine.prove_equivalence(
                (x | y) - (x & y),
                x ^ y,
                options=opts,
            )
            mock_set_option.assert_not_called()


if __name__ == "__main__":
    unittest.main()
