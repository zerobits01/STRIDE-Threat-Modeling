import base64
import sys
import xml.etree.ElementTree as ET
import zlib
from typing import List
from urllib.parse import unquote


def decode_drawio(path: str='test-dfd.xml') -> str:
    mytree = ET.parse(path)
    myroot = mytree.getroot()
    elem = myroot.findall('diagram')
    if len(elem) < 1:
        print("the input file is not valid")
        exit(1)
    
    txt = elem[0].text
    result = zlib.decompress(
        base64.b64decode(txt),
        wbits=-15
    )
    xml = unquote(result)
    return xml


def read_xml_file_as_str(path: str) -> List[str]:
    f = open(path, mode='r')
    read_file = f.readlines()
    f.close()
    return ''.join(read_file)


def write_output(path: str, to_write: List[str]) -> bool:
    with open(path, 'w+') as f:
        f.writelines(to_write)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        txt = decode_drawio(sys.argv[1])
        print(txt)
    else:
        print("please enter input file")
