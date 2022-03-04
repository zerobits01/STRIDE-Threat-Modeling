import xml.etree.ElementTree as ET
from utils.xml_types import GROUP, PROCESS,\
        DATA_STORE, EXT_USER, FLOW


class DFD:
    
    def __init__(self):
        self.processes = []
        self.data_stores = []
        self.external_users = []
        self.flows = []
        self.boundaries = []

    def __str__(self):
        return str(
            self.__dict__
        )

    def __repr__(self):
        return str(
            self.__dict__
        )


def _add_to_dfd(dfd, cell):
    if GROUP == cell.attrib['style']:
        dfd.boundaries.append(cell)
    elif PROCESS in cell.attrib['style']:
        dfd.processes.append(cell)
    elif DATA_STORE in cell.attrib['style']:
        dfd.data_stores.append(cell)
    elif EXT_USER == cell.attrib['style']:
        dfd.external_users.append(cell)
    elif FLOW in cell.attrib['style']:
        dfd.flows.append(cell)

def convert_xml_to_dfd(data: str) -> DFD:
    dfd = DFD()
    mytree = ET.ElementTree(ET.fromstring(data))
    myroot = mytree.getroot()
    for x in myroot:
        all_cells = x.findall('mxCell')
        for cell in all_cells:
            if 'style' in cell.attrib:
                _add_to_dfd(dfd, cell)
    return dfd

