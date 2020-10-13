"""Decodes PBNano based upon protobuf fields definitions"""

__appname__ = "decode_pbnano.py"
__author__  = "Mark Kirschenbaum (Trunk/Hypoxic)"
__version__ = "0.0pre0"
__license__ = "MIT"


import sys
from struct import *
import binascii
import os
import json
import pprint
import argparse

BASE_ADDRESS = 0x3F420110

PB_LTYPE_MASK = 0x0F

type_attribs = {
"PB_LTYPE_VARINT"  :0x00, #/* int32, int64, enum, bool */
"PB_LTYPE_UVARINT" :0x01, #/* uint32, uint64 */
"PB_LTYPE_SVARINT" :0x02, #/* sint32, sint64 */
"PB_LTYPE_FIXED32" :0x03, #/* fixed32, sfixed32, float */
"PB_LTYPE_FIXED64" :0x04, #/* fixed64, sfixed64, double */

# Marker for last packable field type. */
"PB_LTYPE_LAST_PACKABLE" :0x04,

# Byte array with pre-allocated buffer.
# data_size is the length of the allocated PB_BYTES_ARRAY structure. */
"PB_LTYPE_BYTES" :0x05,

# String with pre-allocated buffer.
# data_size is the maximum length. */
"PB_LTYPE_STRING" :0x06,

# Submessage
# submsg_fields is pointer to field descriptions */
"PB_LTYPE_SUBMESSAGE" :0x07,

# Extension pseudo-field
# The field contains a pointer to pb_extension_t 
"PB_LTYPE_EXTENSION" :0x08,

# Byte array with inline, pre-allocated byffer.
# data_size is the length of the inline, allocated buffer.
# This differs from PB_LTYPE_BYTES by defining the element as
# pb_byte_t[data_size] rather than pb_bytes_array_t. 
"PB_LTYPE_FIXED_LENGTH_BYTES" :0x09,

# Number of declared LTYPES
"PB_LTYPES_COUNT" :0x0A,
}

PB_HTYPE_MASK = 0x30

requirements = {
"PB_HTYPE_REQUIRED"  :0x00,
"PB_HTYPE_OPTIONAL"  :0x10,
"PB_HTYPE_REPEATED"  :0x20,
"PB_HTYPE_ONEOF"     :0x30}

def auto_int(x):
    return int(x, 0)

def swap32(i):
    return unpack("<I", pack(">I", i))[0]

def toSigned32(n):    
    n = n & 0xffffffff
    return n | (-(n & 0x80000000))
    
class field:
    
    def __init__(self, fbin):
        eof = True
        
        buf = fbin.read(25)
        
        if not buf:
            print("reached eof")
            self.eof = True
            return
        
        for b in buf:
            if b != 0:
                eof = False
        
        if eof:
            #print("end of pbnano fields")
            self.eof = True
            return
        else:
            #(self.tag,self.typ,self.data_offset,self.size_offset,self.data_size,self.array_size,self.ptr) = unpack(">IBIIIII", buf)
            #print(binascii.hexlify(buf))
            (self.tag,self.typ,self.data_offset,self.size_offset,self.data_size,self.array_size,self.ptr) = unpack("<IBIIIII", buf)
            
            self.data_offset = toSigned32(self.data_offset)
            self.size_offset = toSigned32(self.size_offset)
            self.data_size = toSigned32(self.data_size)
            self.array_size = toSigned32(self.array_size)
            
            if(self.ptr != 0):
                self.offset = self.ptr - BASE_ADDRESS
            else:            
                self.offset = None
            
            self.submsg = False
            if(self.typ & PB_LTYPE_MASK == type_attribs["PB_LTYPE_SUBMESSAGE"]):
                self.submsg = True
                
            self.eof = False
            
    def create_json(self):
        s = self.decode_type()
        jobject = {"tag": self.tag,
                    "taghex": hex(self.tag),
                   "type": s,
                    "data_offset":self.data_offset,
                    "size_offset":self.size_offset,
                    "data_size":self.data_size,
                    "array_size":self.array_size,
                    "submessage" : "None"}
        #return(json.dumps(jobject))                        
        return(jobject)                        
                    
            
            
    def decode_type(self):
        t = self.typ
        
        s = []
        
        for key in type_attribs:
            a = type_attribs[key]
            
            if ((t & PB_LTYPE_MASK) == a):
                # print("attribute mask %x" % a)
                s.append(key)
                
        for key in requirements:
            a = requirements[key]
            
            if ((t & PB_HTYPE_MASK) == a):
                #print("requirements mask %x" % a)
                s.append(key)                
        
        s = " | ".join(s)                
        return(s)

def expand_subfield(fbin, fields, jobject):
    count = 0
    
    while True:
            
        f = field(fbin)
        
        count += 1
        
        if f.eof:
            #print("ending")
            return
        else:
            print("\ntype: %x" % f.typ)
            print("Tag: %x" % f.tag)
            print("data_offset: %x" % f.data_offset)
            print("size_offset: %d" % f.size_offset)
            print("data_size: %x" % f.data_size)
            print("array_size: %x" % f.array_size)
            
            if f.offset:
                print("offset: %x" % f.offset)
                
            print("Attributes: %s" % f.decode_type())
            
            fields.append(field)
            
            #json
            parent = f.create_json()
            
            if(f.submsg):
                print("recursive expand_subfield")
                
                # stream pointer
                last_loc = fbin.tell()
                fbin.seek(f.offset)
                check = fbin.tell()
                                                
                if(check == f.offset):
                    print("trying %x %x" % (f.offset, check))
                    children = []
                    expand_subfield(fbin, fields, children)
                    
                    if children:
                        parent["submessage"] = children
                                        
                    fbin.seek(last_loc)
                else:
                    print("seek set failed tried %x" % f.offset)   
            
            jobject.append(parent)                                                     

####

def main():
    parser = argparse.ArgumentParser(description='Parses a PBNano file for the various message structures and writes it to a json file')

    parser.add_argument("--file", "-f", type=str, required=True, help="File which contains the pbnano compiled structure")
    parser.add_argument("--base", "-b", type=auto_int, required=False, help="base address where you found the pbnano definition")
    args = parser.parse_args()

    filename = args.file
    
    if not args.base:
        args.base = 0x3F420110

    BASE_ADDRESS = args.base
    
    fsize = os.path.getsize(filename)
    print("unpacking %s dize %x" %(filename, fsize))

    with open(filename,'rb') as fbin:
        fields = []
        jobject = []
        
        expand_subfield(fbin, fields, jobject)    
        
        """
        j = json.dumps(jobject)
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(j)
        """
        
        with open('data.json', 'w', encoding='utf-8') as f:
            json.dump(jobject, f, ensure_ascii=False, indent=4)

if __name__ == "__main__":
    main()
    
        
             