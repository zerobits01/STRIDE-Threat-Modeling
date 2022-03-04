'''
using this for decoding the diagrams: https://jgraph.github.io/drawio-tools/tools/convert.html
defalate mode

=============================

using drawio for drawing

=============================


we can say each group means a boundary

shapes:
    1. process ==========================> ellipse(contains)
    2. data store =======================> shape=mxgraph.ios7ui.horLines;(contains)
    3. the boundary dont check this =====> rounded=0;whiteSpace=wrap;html=1;dashed=1;(exact)
    4. external user ====================> rounded=0;whiteSpace=wrap;html=1;(exact)
    5. flow =============================> edgeStyle=orthogonalEdgeStyle;(contains)
    
'''

GROUP       = "group"                               # exact equal, groups are style="group"
PROCESS     = "ellipse"                             # contains 
DATA_STORE  = "shape=mxgraph.ios7ui.horLines;"      # contains
DATA_STORE1 = "shape=partialRectangle"
EXT_USER    = "rounded=0;whiteSpace=wrap;html=1;"   # contains
FLOW        = "edgeStyle=orthogonalEdgeStyle;"      # contains