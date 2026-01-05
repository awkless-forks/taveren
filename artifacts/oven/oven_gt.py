import networkx

oven = networkx.DiGraph()

node0 = (("OvenState", "IDLE"), ("OvenStatus", "OFF"))
node1 = (("OvenState", "TOO_HOT"), ("OvenStatus", "OFF"))
node2 = (("OvenState", "PREHEAT"), ("OvenStatus", "OFF"))
node3 = (("OvenState", "PREHEAT"), ("OvenStatus", "ON"))
node4 = (("OvenState", "COOK"), ("OvenStatus", "ON"))
node5 = (("OvenState", "COOK"), ("OvenStatus", "OFF"))
node6 = (("OvenState", "COOL"), ("OvenStatus", "ON"))
node7 = (("OvenState", "COOL"), ("OvenStatus", "OFF"))
node8 = (("OvenState", "COMPLETE"), ("OvenStatus", "OFF"))


oven.add_node(node0)
oven.add_node(node2)
oven.add_node(node1)
oven.add_node(node3)
oven.add_node(node4)
oven.add_node(node5)
oven.add_node(node6)
oven.add_node(node7)
oven.add_node(node8)


oven.add_edge(
    node0, node1,
    time_delta=None,
    temp=51.0,
    label="time_delta=None, temp>=50.0"
)

oven.add_edge(
    node1, node0,
    time_delta=None,
    temp=49.0,
    label="time_delta=None, temp<50.0"
)

oven.add_edge(
    node0, node2,
    time_delta=None,
    temp=None,
    label="time_delta=None, temp=None"
)

oven.add_edge(
    node2, node3,
    time_delta=None,
    temp=None,
    label="time_delta=None, temp=None"
)

oven.add_edge(
    node3, node4,
    time_delta=None,
    temp=151.0,
    label="time_delta=None, temp>=150.0"
)

oven.add_edge(
    node4, node5,
    time_delta=None,
    temp=171.0,
    label="time_delta=None, temp>170.0"
)

oven.add_edge(
    node5, node4,
    time_delta=None,
    temp=149.0,
    label="time_delta=None, temp<150.0"
)

oven.add_edge(
    node4, node6,
    time_delta=9000,
    temp=None,
    label="time_delta>9000, temp=None"
)

oven.add_edge(
    node5, node7,
    time_delta=9000,
    temp=None,
    label="time_delta>9000, temp=None"
)

oven.add_edge(
    node7, node8,
    time_delta=None,
    temp=49.0,
    label="time_delta=None, temp<=50.0"
)

oven.add_edge(
    node6, node8,
    time_delta=None,
    temp=49.0,
    label="time_delta=None, temp<=50.0"
)


networkx.drawing.nx_agraph.write_dot(oven, "oven_gt.dot")

ref = oven
