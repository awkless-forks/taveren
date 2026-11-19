Usage
=====

Installation
------------

Ta'veren requires Python 3.12. Install the released package from PyPI::

   pip install taveren

The optional ``graphviz`` extra installs ``pygraphviz``, used to write recovered
state graphs as ``.dot`` files. It, and the ``test`` extra, need the graphviz
development headers::

   sudo apt-get install graphviz graphviz-dev
   pip install 'taveren[graphviz]'

To run the test suite, install from a clone of the repository with
`uv <https://docs.astral.sh/uv/>`_::

   uv sync --extra test

or with pip inside a virtualenv::

   python3.12 -m venv .venv
   . .venv/bin/activate
   pip install -e '.[test]'

Importing :mod:`taveren` applies the patches in :mod:`taveren.angr_compat` to
the stock angr release.

Command-line tools
------------------

Installing the package provides one command per pre-processing stage::

   taveren-scan-cycle <binary>                              # detect the scan cycle function
   taveren-init-finder <binary> <scan-cycle-func>           # rank initialization function candidates
   taveren-statevars <binary> <scan-cycle-func>... [-o LOG] # identify state variables

Functions are given as a hex address (``0x42C034``) or a symbol name
(``loop``). See :mod:`taveren.scan_cycle`, :mod:`taveren.init_finder` and
:mod:`taveren.statevars`.

Testing the API examples
------------------------

Like Rust doc tests, the examples in the API reference are executable: run them with
pytest's doctest support::

   uv run pytest --doctest-modules src/taveren

Examples that need a PLC binary and a long analysis are marked ``# doctest: +SKIP``
(the equivalent of Rust's ``no_run``); they are rendered but not executed. Shared example
data, such as the state graph used throughout :mod:`taveren.rule_verifier`, is provided by
``conftest.py`` at the repository root.

Building this documentation
---------------------------

::

   uv sync --extra docs
   uv run sphinx-build -M html docs docs/_build

The HTML output is written to ``docs/_build/html``.
