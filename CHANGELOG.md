# Changelog

All notable changes since the upstream Ta'veren release (`31539fe`).

## [1.0.0] - 2026-11-19

### Added
- `StateGraphRecovery` (`proj.analyses.StateGraphRecovery`): a ready-made state
  graph recovery analysis for programs whose inputs are integer variables. It
  reads the inputs from the environment model, so typical Beremiz/OpenPLC
  programs no longer need a target-specific `StateGraphRecoveryBase` subclass.
  It explores clock advances and each input on its own; float, double and pin
  inputs are rejected with `NotImplementedError`.
- PyPI packaging metadata: README as the long description, `BSD-2-Clause`
  license expression, authors, maintainers, project URLs, keywords and
  classifiers.
- `graphviz` extra for `pygraphviz`.

### Changed
- Removed commented-out and quoted-out code from the ten remaining
  per-target analyses in `tests/*/state_graph_recovery.py` (10,319 to 7,276
  lines). Each file's syntax tree is unchanged apart from the removed string
  blocks, so they run exactly as before. These targets keep their own
  analyses: they model states and transitions differently from
  `StateGraphRecovery`, so migrating them would change their graphs.
- `water_tank_one_sensor` uses `StateGraphRecovery` instead of its own
  751-line analysis, which is removed. The recovered graph is identical: the
  same 4 nodes and 7 edges, with the same deltas, sources and labels.
- **pygraphviz is no longer a core dependency.** The library never imports it;
  it is only needed to write `.dot` files. It moved to the new `graphviz` extra
  and the `test` extra, so `pip install taveren` no longer needs the graphviz
  headers.
- The sdist now contains only the package, README, LICENSE, CHANGELOG and
  `pyproject.toml`. The PLC fixtures, experiments and docs stay in the git
  repository.
- README links are absolute GitHub URLs so they work on PyPI.
- SPDX headers now say `BSD-2-Clause`, matching `LICENSE`.
- The repository is now REUSE 3.3 compliant: SPDX headers in `src/taveren`,
  license texts in `LICENSES/`, and a `REUSE.toml` that records the copyright
  and license of data, binaries and third-party fixtures (Beremiz, ArduPilot,
  the Arduino SAMD core, the Intel HEX parser and the vending machine sketch).
- **Dependencies now come from PyPI.** Ta'veren depends on `angr>=10.0.1,<11`
  instead of git submodules pinned to angr 9.2.189 with patched angr/claripy
  forks. claripy now ships inside angr as `angr.claripy`. angr-management is an
  optional `gui` extra. `git submodule update` is no longer needed:
  `uv sync --extra test` sets up everything. (`2e68325`)
- **Fork patches moved into the package.** The new `taveren.angr_compat` module
  re-applies the former angr/claripy fork patches on top of stock angr when
  `taveren` is imported: the `div`/`fmod` libc SimProcedures, the PPC64 `r12`
  call-state fix, THUMB look-back bytes for IT-block lifting, and the fork's
  extra claripy canonicalization rules. (`2e68325`)
- Ported the code to the angr 10 APIs: `from angr import claripy`, replacements
  for the removed `make_like()`/`leaf_asts()`, the new floating-point
  expression argument layout, and angr 10's AIL (`AILBlockViewer`,
  `Call` as an expression, `ins_addr` in tags). (`2e68325`)
- Replaced the `extremely-simple-setup.sh` bootstrap script with a uv-managed
  `pyproject.toml`. (`bae0945`)
- Restructured the project into a proper `src/taveren` package. The
  pre-processing stages install as console scripts: `taveren-scan-cycle`,
  `taveren-init-finder` and `taveren-statevars`. (`7bc3826`, `150204f`)
- Moved every analysis into a pytest suite under `tests/`, with binaries and
  data in `tests/fixtures/` and paper-reproduction scripts, outputs and logs in
  `experiments/`. (`7bc3826`, `d6dcb4f`, `17b1209`, `40cb7f1`, `b1af1ff`,
  `8459855`, `d212b78`, `150204f`)
- Deduplicated the per-test `state_graph_recovery.py` copies into a shared
  `StateGraphRecoveryBase` and helpers (`env_model`, `hooks`, `callgraph`).
  Each test keeps only the methods that differ. (`150204f`, `3ea9faa`)
- Converted `ihex_parser.json` to the standard environment-model keys.
  (`3ea9faa`)
- Formatted the codebase with black. (`ac50b57`)

### Fixed
- **arducopter_flip on angr 10:** load the real `libm`
  (`auto_load_libs=True`), since cle 10 no longer loads shared libraries by
  default. Without it, `fabsf`/`sqrtf` returned unconstrained values and
  execution forked. (`2e68325`)
- **arducopter_flip delta discovery on angr 10:** restored signed results from
  `solver.min/max(signed=True)`, dropped `x ± 0` in constraints, and matched
  the new `tv_sec + delta <= c` time-bound shape. (`c8c61c2`)
- angr analyses registered under one shared name, so tests could silently run
  another suite's analysis. Each suite now registers a unique name. (`d6dcb4f`,
  `f7e3844`)
- water_tank_one_sensor: `SensorExclusionRule` used an impossible `and`
  condition. The test now asserts that the blind-trust vulnerability is
  detected. (`d78af55`)
- vending_machine: `GiveChange` over-counted the running total. (`d5cbc0e`)
- traffic_lights: `MinDelayRule_Orange.node_b` kept expanding past matches.
  (`d5cbc0e`)
- arducopter_flip: `test_flip` could pass without checking anything.
  (`d5cbc0e`)
- `ipdb` breakpoints, which crashed because ipdb wasn't a dependency, are
  replaced with descriptive exceptions. (`3ea9faa`)
- Fixed broken traffic-tl9 and water-tank targets in the statevars `run.sh`.
  (`150204f`)

### Removed
- The git submodules under `external/` and `.gitmodules`. They were added in
  `6b34628` and removed in `2e68325`.
- Unreachable Patcherex/raw-binary code in `apply_patch`, and its misleading
  startup warning. (`3ea9faa`)
- Dead imports and code across the test suite. (`d5cbc0e`)
- Outdated screenshots in `figs/`. (`c46a20c`)

### Performance
- BFS rule helpers use a `set` and `deque` instead of lists, so traversal is no
  longer O(n²). (`d5cbc0e`)

### Known issues
- Every target except car_wash has been run on angr 10 before and after the
  dead-code removal and recovers identical graphs both times. All tests pass
  except:
  - `test_elevator[AVR]` fails with `ModuleNotFoundError: angr_platforms`.
    AVR support lives in angr-platforms, which is not on PyPI and is no longer
    vendored as a submodule. `test_elevator[ARM]` passes.
  - `test_oven` is skipped: no variable-description JSON ships for it.
    (`d5cbc0e`)
- arducopter_flip recovers the same 12 nodes as on the old deps (16 edges
  instead of 18). One roll-sensor step changed from −17998 to −8998: old
  claripy's expression shape caused a bound to be skipped, and −8998 is the
  value consistent with that branch.
- car_wash is slow. `test_carwash[x86]` passes in about an hour;
  `test_carwash[arm]` and `test_policy` have not yet completed a run on
  angr 10.
