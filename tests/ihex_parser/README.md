This folder contains the analysis code for ihex parser (Appendix G).

[`state_graph_recovery.py`](state_graph_recovery.py) is the FSM recovery analysis used for this target.
[`ihex.dot`](ihex.dot) is the FSM recovered for the paper; running the test writes a fresh one to `graphs/`.

To start the analysis, from the repository root, run `pytest tests/ihex_parser`
