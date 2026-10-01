import networkx


elev_gt = networkx.MultiDiGraph()

node1 = (('level', 1), ('dir', 0))
node2 = (('level', 2), ('dir', 1))
node3 = (('level', 3), ('dir', 1))
node4 = (('level', 4), ('dir', 1))
node5 = (('level', 1), ('dir', -1))
node6 = (('level', 2), ('dir', 0))
node7 = (('level', 2), ('dir', -1))
node8 = (('level', 3), ('dir', 0))
node9 = (('level', 3), ('dir', -1))
node10 = (('level', 4), ('dir', 0))


elev_gt.add_node(node1)
elev_gt.add_node(node2)
elev_gt.add_node(node3)
elev_gt.add_node(node4)
elev_gt.add_node(node5)
elev_gt.add_node(node6)
elev_gt.add_node(node7)
elev_gt.add_node(node8)
elev_gt.add_node(node9)
elev_gt.add_node(node10)


elev_gt.add_edge(
    node1, node1,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node1, node2,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node1, node3,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)
elev_gt.add_edge(
    node1, node4,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)


elev_gt.add_edge(
    node2, node3,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)
elev_gt.add_edge(
    node2, node4,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)
elev_gt.add_edge(
    node2, node5,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node2, node6,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)


elev_gt.add_edge(
    node3, node4,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)
elev_gt.add_edge(
    node3, node5,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node3, node7,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node3, node8,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)


elev_gt.add_edge(
    node4, node5,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node4, node7,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node4, node9,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)
elev_gt.add_edge(
    node4, node10,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)


elev_gt.add_edge(
    node5, node1,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node5, node2,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node5, node3,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)
elev_gt.add_edge(
    node5, node4,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)


elev_gt.add_edge(
    node6, node3,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)
elev_gt.add_edge(
    node6, node4,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)
elev_gt.add_edge(
    node6, node5,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node6, node6,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)


elev_gt.add_edge(
    node7, node3,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)
elev_gt.add_edge(
    node7, node4,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)
elev_gt.add_edge(
    node7, node5,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node7, node6,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)


elev_gt.add_edge(
    node8, node4,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)
elev_gt.add_edge(
    node8, node5,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node8, node7,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node8, node8,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)


elev_gt.add_edge(
    node9, node4,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)
elev_gt.add_edge(
    node9, node5,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node9, node7,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node9, node8,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)


elev_gt.add_edge(
    node10, node5,
    btn1=1, btn2=0, btn3=0, btn4=0,
    label="btn1=1\nbtn2=0\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node10, node7,
    btn1=0, btn2=1, btn3=0, btn4=0,
    label="btn1=0\nbtn2=1\nbtn3=0\nbtn4=0",
)
elev_gt.add_edge(
    node10, node9,
    btn1=0, btn2=0, btn3=1, btn4=0,
    label="btn1=0\nbtn2=0\nbtn3=1\nbtn4=0",
)
elev_gt.add_edge(
    node10, node10,
    btn1=0, btn2=0, btn3=0, btn4=1,
    label="btn1=0\nbtn2=0\nbtn3=0\nbtn4=1",
)

networkx.drawing.nx_agraph.write_dot(elev_gt, "elev_ref.dot")

ref = elev_gt
