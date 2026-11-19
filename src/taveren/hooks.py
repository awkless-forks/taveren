# SPDX-FileCopyrightText: 2026 Jason Pena <jpalex@nmsu.edu>
# SPDX-FileCopyrightText: 2026 The Arizona Board of Regents
#
# SPDX-License-Identifier: BSD-2-Clause

"""angr hooks for PLC runtime functions that FSM recovery should not execute.

Examples:
    Typical setup for a Beremiz-generated PLC binary before recovering its state graph:

    >>> import angr
    >>> from taveren import hook_py_extensions, normalize_timespec
    >>> proj = angr.Project("tests/fixtures/packaging_sfc/build/packaging_sfc.so",
    ...                     auto_load_libs=False)  # doctest: +SKIP
    >>> cfg = proj.analyses.CFG()  # doctest: +SKIP
    >>> hook_py_extensions(proj, cfg)  # doctest: +SKIP
    >>> proj.hook_symbol("__normalize_timespec", normalize_timespec())  # doctest: +SKIP
"""

import angr


class normalize_timespec(angr.SimProcedure):
    """
    A no-op replacement for the Beremiz runtime's ``__normalize_timespec``.

    Ta'veren symbolizes and advances the PLC clock itself, so the runtime must not renormalize it.

    Examples:
        >>> proj.hook_symbol("__normalize_timespec", normalize_timespec())  # doctest: +SKIP
    """

    def run(self):
        return None


def hook_py_extensions(proj, cfg):
    """
    Stub out the Beremiz runtime's Python extension and debug publishing functions.

    ``PYTHON_EVAL_body__``, ``PYTHON_POLL_body__``, ``__publish_debug`` and ``__publish_py_ext`` are replaced with
    procedures that return an unconstrained value, since they talk to a Python interpreter that symbolic execution
    cannot model.

    Args:
        proj: The angr project of the PLC binary.
        cfg: A CFG of ``proj``, used to look up the functions by name.

    Raises:
        KeyError: If any of the four functions is missing from the binary.

    Examples:
        >>> proj = angr.Project("tests/fixtures/packaging_sfc/build/packaging_sfc.so",
        ...                     auto_load_libs=False)  # doctest: +SKIP
        >>> cfg = proj.analyses.CFG()  # doctest: +SKIP
        >>> hook_py_extensions(proj, cfg)  # doctest: +SKIP
        >>> proj.is_hooked(cfg.kb.functions["__publish_debug"].addr)  # doctest: +SKIP
        True
    """
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
