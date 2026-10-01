import networkx

vend = networkx.DiGraph()

node1 = ("WAIT")
node2 = ("TWENTYFIVE")
node3 = ("FIFTY")
node4 = ("GIVE_CHANGE")
node5 = ("DROP_CAN")


vend.add_node(node1)
vend.add_node(node2)
vend.add_node(node3)
vend.add_node(node4)
vend.add_node(node5)

vend.add_edge(
    node1,
    node2,
    dollar=None,
    quarter=1,
    label="insert quarter",
)
vend.add_edge(
    node1,
    node4,
    dollar=1,
    quarter=0,
    label="insert dollar",
)
vend.add_edge(
    node2,
    node3,
    dollar=None,
    quarter=1,
    label="insert quarter",
)
vend.add_edge(
    node4,
    node5,
    dollar=None,
    quarter=None,
    label="",
)
vend.add_edge(
    node3,
    node5,
    dollar=None,
    quarter=1,
    label="insert quarter",
)
vend.add_edge(
    node5,
    node1,
    dollar=None,
    quarter=None,
    label="",
)

networkx.drawing.nx_agraph.write_dot(vend, "vend_gt.dot")

ref = vend
