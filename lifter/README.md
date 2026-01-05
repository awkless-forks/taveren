This folder contains the analysis code for warehouse lifter, and experiment that analyze the impact of inaccurate environment models on Ta'veren's ability for FSM recovery and BTV discovery.

[`state_graph_recovery`](state_graph_recovery/) is the library for FSM recovery and policy verification.  
[`test`](test/) contains test files.  
[`graphs`](test/graphs/) contains the generated FSMs.  
[`sensitivity_analysis`](test/sensitivity_analysis/) contains various scenarios of inaccurate environment models.

To start the analysis, in `test` folder run `python test_lifter.py`.