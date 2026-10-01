"""angr hooks for PLC runtime functions that FSM recovery should not execute."""

import angr


class normalize_timespec(angr.SimProcedure):
    def run(self):
        return None


def hook_py_extensions(proj, cfg):
    """Stub out the Beremiz runtime's Python extension and debug publishing functions."""
    proj.hook(
        cfg.kb.functions["PYTHON_EVAL_body__"].addr,
        angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](),
    )
    proj.hook(
        cfg.kb.functions["PYTHON_POLL_body__"].addr,
        angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](),
    )
    proj.hook(
        cfg.kb.functions["__publish_debug"].addr,
        angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](),
    )
    proj.hook(
        cfg.kb.functions["__publish_py_ext"].addr,
        angr.SIM_PROCEDURES["stubs"]["ReturnUnconstrained"](),
    )
