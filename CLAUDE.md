# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Ta'veren (NDSS 2026) recovers the finite state machine implemented by a PLC binary and model-checks safety
policies against it to find blind-trust vulnerabilities. This repo is a fork that moved the code onto stock
angr 10 from PyPI and packaged it as `src/taveren`. Python is pinned to 3.12 (`>=3.12,<3.13`).

## Commands

```
uv sync --extra test                                  # set up (add --extra docs / --extra gui as needed; uv sync drops unlisted extras)
uv run pytest                                         # full suite (tests/ only; slow, runs symbolic execution on real binaries)
uv run pytest tests/water_tank_one_sensor             # one target
uv run pytest "tests/car_wash/test_car_wash.py::test_carwash[x86]"   # one (parametrized) test
uv run pytest --doctest-modules src/taveren           # docstring examples (fast)
uv run sphinx-build -M html docs docs/_build -W --keep-going   # docs must build warning-free
uv build                                              # sdist + wheel
reuse lint                                            # REUSE 3.3 compliance (must stay passing)
```

The `test` extra pulls in `pygraphviz`, which needs `graphviz graphviz-dev` system packages. The core
package does not depend on pygraphviz. Code is formatted with black.

## Architecture

**Pipeline.** Pre-processing finds three inputs for each binary: the scan cycle function
(`scan_cycle.py`), init function candidates (`init_finder.py`) and state variables (`statevars.py`). Each
module has a `main(argv)` exposed as the `taveren-scan-cycle`, `taveren-init-finder` and
`taveren-statevars` console scripts. A test then runs the init function with `proj.factory.callable`, loads
the target's environment-model JSON (inputs/outputs: addresses, sizes, types) via
`env_model.generate_field_desc` into `AbstractStateFields`, runs a state graph recovery analysis from the
scan cycle function, and checks rules with `RuleVerifier`.

**`angr_compat.py` must load first.** `taveren/__init__.py` imports it before anything else. It
monkey-patches stock angr/claripy with what the old angr/claripy forks used to carry (libc `div`/`fmod`
SimProcedures, a PPC64 `r12` fix, THUMB look-back bytes, extra claripy simplifications). Use
`from angr import claripy`, not the standalone `claripy` package.

**State graph recovery.** `StateGraphRecoveryBase` (an angr `Analysis` in `state_graph_recovery.py`) holds
the shared machinery: symbolizing the time counter for each runtime flavour (Beremiz, Arduino, Simulink),
discovering time deltas, running one scan cycle (`_traverse_one`) and the dedup-edge `MultiDiGraph`.
`StateGraphRecovery` in the same file is the generic analysis built on it: a breadth-first `traverse()` that
explores clock advances and each integer input from the env model on its own, with edge attributes
`time_delta*` and `<input lowercased>_delta/_constraint/_src`. `water_tank_one_sensor` uses it.

The other targets still have their own `tests/<target>/state_graph_recovery.py` subclass, a copy of the same
loop with inputs hard-coded and much dead code. Six of them (water_tank_two_sensors, packaging, car_wash,
lifter, abortsystem, vending_machine) differ only in how inputs are combined (jointly or as a Cartesian
product) and in float step extraction, so they are candidates for `StateGraphRecovery`. traffic_lights,
arducopter_flip, elevator and ihex_parser genuinely need custom code. When migrating one, record the old
graph first and check the new one is identical. Subclasses register with
`AnalysesHub.register_default("<UniqueName>", ...)`. **Every target must use a unique registration name.**
A shared name lets one suite silently run another suite's analysis.

**Rules** (`rule_verifier.py`): subclass `IllegalNodeBaseRule`, `IllegalTransitionBaseRule`,
`MinDelayBaseRule`/`MaxDelayBaseRule`, or `BaseRule.eval` for a custom check over the graph. Nodes are
tuples of `(field, value)` pairs. Edges carry `time_delta` and other `*_delta` attributes, which are `None`
when the transition doesn't depend on them. `root_cause.py` traces violations back to code, and `apis.py`
applies patches.

**Layout.** Tests use binaries in `tests/fixtures/<target>/build/` (Beremiz/OpenPLC `.so`, Arduino `.elf`,
plus `binaries/` for ArduCopter, ihex parser and the Simulink launch-abort `.exe`), loaded by paths relative
to the test file. `experiments/` holds paper-reproduction scripts and saved outputs. It is not part of the
package or test suite.

## Conventions and gotchas

- Docstrings use Google style with `Examples:`, and the examples are doctests. Mark ones that need a binary
  or a long analysis with `# doctest: +SKIP`. Shared doctest fixtures live in the root `conftest.py`.
- ArduCopter needs `auto_load_libs=True` (real `libm`). cle 10 no longer loads shared libraries by default,
  and without libm execution forks on unconstrained `fabsf`/`sqrtf`.
- Only `arducopter_flip` has been validated on angr 10 so far, and `test_oven` is skipped (no variable JSON).
  See `CHANGELOG.md` "Known issues".
- Licensing is BSD-2-Clause. New source files need SPDX headers (`reuse annotate`). Data, binaries and
  third-party fixtures are covered in `REUSE.toml`; add an annotation there when adding fixtures.
- The sdist includes only `src/taveren` plus top-level metadata (see `[tool.hatch.build.targets.sdist]`).
  Fixtures are not shipped.
