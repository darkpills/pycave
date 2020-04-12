#!/usr/bin/python3

""" pycave.py: Dirty code to find code caves in Portable Executable files"""

__author__ = 'axcheron'
__license__ = 'Apache 2'
__version__ = '0.1'

import argparse
import pefile
import sys

def getCharacteristics(characteristics):
    result = ""
    
    if (characteristics & 0x40000000):
        result+="R"
    else:
        result+="-"
    if (characteristics & 0x40000000):
        result+="W"
    else:
        result+="-"
    if (characteristics & 0x00000020 > 0 or characteristics & 0x20000000 > 0):
        result+="X"
    else:
        result+="-"

    return result


def pycave(file_name, cave_size, lookupByte, base):

    image_base = int(base, 16)
    min_cave = cave_size
    fname = file_name
    pe = None

    try:
        pe = pefile.PE(fname)
    except IOError as e:
        print(e)
        sys.exit(0)
    except pefile.PEFormatError as e:
        print("[-] %s" % e.args[0])
        sys.exit(0)

    print("[+] Minimum code cave size: %d" % min_cave)
    print("[+] Image Base:  0x%08X" % image_base)
    print("[+] Loading \"%s\"..." % fname)

    # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040
    is_aslr = pe.OPTIONAL_HEADER.DllCharacteristics & 0x0040

    if is_aslr:
        print("\n[!] ASLR is enabled. Virtual Address (VA) could be different once loaded in memory.")

    fd = open(fname, "rb")

    VAEnd = 0

    print("\n[+] Looking for code caves of 0x%02X..." % lookupByte)
    for section in pe.sections:


        # Print section data
        RAStart = section.PointerToRawData
        RAEnd = section.PointerToRawData + section.SizeOfRawData
        VAStart = image_base + section.VirtualAddress

        # Special case where we have space between sections
        if VAEnd != 0 and VAStart - VAEnd >= min_cave and lookupByte == 0x00:
                print("[+]\tCode cave found \tSize: %d bytes \tRA: N/A \tVA: 0x%08X (intersection space)"
                    % ((VAStart - VAEnd), VAEnd))

        VAEnd = image_base + section.VirtualAddress + section.Misc_VirtualSize
        print("[i] %s \tRA: 0x%08X-0x%08X\tVA: 0x%08X-0x%08X\tFlags: %s" 
            % (section.Name.decode(), RAStart, RAEnd, VAStart, VAEnd, getCharacteristics(section.Characteristics)))

        if section.SizeOfRawData != 0:
            pos = 0
            count = 0
            fd.seek(section.PointerToRawData, 0)
            data = fd.read(section.SizeOfRawData)

            for byte in data:
                pos += 1
                if byte == lookupByte:
                    count += 1
                else:
                    if count >= min_cave:
                        raw_addr = RAStart + pos - count - 1
                        vir_addr = VAStart + pos - count - 1

                        print("[+]\tCode cave found \tSize: %d bytes \tRA: 0x%08X \tVA: 0x%08X"
                              % (count, raw_addr, vir_addr))
                    count = 0

    pe.close()
    fd.close()

if __name__ == "__main__":

    if sys.version_info[0] < 3:
        raise Exception("Use using Python 3")

    '''This function parses and return arguments passed in'''
    # Assign description to the help doc
    parser = argparse.ArgumentParser(
        description="Find code caves in PE files")

    # Add arguments
    parser.add_argument("-f", "--file", dest="file_name", action="store", required=True,
                        help="PE file", type=str)

    parser.add_argument("-s", "--size", dest="size", action="store", default=300,
                        help="Min. cave size", type=int)

    parser.add_argument("-b", "--byte", dest="lookupByte", action="store", default="0x00",
                        help="Lookup byte in cave, format 0x00", type=str)

    parser.add_argument("-i", "--image-base", dest="imageBase", action="store", default="0x00400000",
                        help="Image base", type=str)

    args = parser.parse_args()
    if args.file_name:
        pycave(args.file_name, args.size, int(args.lookupByte[2:], 16), args.imageBase)
    else:
        parser.print_help()
        exit(-1)
