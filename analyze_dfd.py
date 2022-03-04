import argparse
import xml.etree.ElementTree as ET

from utils.dfd import DFD, convert_xml_to_dfd
from utils.sec_analyze import STRIDEMatrix
from utils.files import read_xml_file_as_str, decode_drawio, write_output


args = argparse.ArgumentParser(description="use it to analyze DFDs for STRIDE base threats")


args.add_argument('-i', '--input', type=str, required=True, help='input file in xml format')
args.add_argument('-o', '--output', type=str, required=True, help='output file to write result on')
args.add_argument('-d', '--deflate', action="store_const", const=True, default=False, 
                    help='use this if the file is not decoded and raw xml from drawio')


def main():
    """main function of the program
    """
    
    '''
    steps:
        0. detecting all elements
        1. creating elements matrix of threats(except groups)
        2. analyzing to find threats and set them
    '''
    try:
        parsed = args.parse_args()

        # read file based on situation
        data_for_dfd = ""
        ouput = ""
        if parsed.deflate:
            data_for_dfd = decode_drawio(parsed.input)
        else:
            data_for_dfd = read_xml_file_as_str(parsed.input)

        # get all elements in DFD
        test_dfd: DFD= convert_xml_to_dfd(data_for_dfd)

        # analyze each item of the dfd and return the whole matrix as string
        output = STRIDEMatrix(
            test_dfd
        ).analyze_stride_matrix_completely()
        print(str(output))

        # write output
        write_output(parsed.output, str(output))
        
    except Exception as e:
        print(f"error occured on line {e.__traceback__.tb_lineno}, detailed info: {e}")    
        # print(e.__traceback__.tb_next)
        # while True:
        #     e = 
        exit(1)
        

if __name__ == "__main__":
    main()