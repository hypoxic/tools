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

wire_types = {
"PB_WT_VARINT" : 0,
"PB_WT_64BIT"  : 1,
"PB_WT_STRING" : 2,
"PB_WT_32BIT"  : 5}

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
            self.eof = True
            return
        else:
            (self.tag,self.typ,self.data_offset,self.size_offset,self.data_size,self.array_size,self.ptr) = unpack("<IBIIIII", buf)
            
            self.data_offset = toSigned32(self.data_offset)
            self.size_offset = toSigned32(self.size_offset)
            self.data_size = toSigned32(self.data_size)
            self.array_size = toSigned32(self.array_size)
            self.subfields = []
            
            if(self.ptr != 0):
                self.offset = self.ptr - memory_base
            else:            
                self.offset = None
            
            self.submsg = False
            if(self.typ & PB_LTYPE_MASK == type_attribs["PB_LTYPE_SUBMESSAGE"]):
                self.submsg = True
                
            self.eof = False

    def add_submessage(self, f):
        self.subfields.append( f )
            
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
            print("\nTag: %x" % f.tag)
            print("Type: %x" % f.typ)
            print("data_offset: %x" % f.data_offset)
            print("size_offset: %d" % f.size_offset)
            print("data_size: %x" % f.data_size)
            print("array_size: %x" % f.array_size)
            
            if f.offset:
                #print("ptr: %x" % f.ptr)
                print("offset: %x" % f.offset)
                
            print("Attributes: %s" % f.decode_type())
            
            #json
            parent = f.create_json()
            
            # check for subfields
            if(f.submsg):
                print("expand_subfield")
                
                # stream pointer
                last_loc = fbin.tell()
                fbin.seek(f.offset)
                check = fbin.tell()
                                                
                if(check == f.offset):
                    children = []
                    fchildern = []
                    expand_subfield(fbin, fields, children)
                    
                    if children:
                        parent["submessage"] = children
                        
                    if fchildern:
                        f.add_submessage(fchildern)                        
                                        
                    fbin.seek(last_loc)
                    
                else:
                    print("seek set failed tried %x" % f.offset)   
            
            #fields.append(field)
            fields.append(f)
            
            jobject.append(parent)                                                     

####

def load_tag(tag, fields):
    for f in fields:
        print(f.tag)

    return f        

#def pb_decode_varint32_eof(fbin, fields):
def pb_decode_varint32_eof(value):
    #decode stream
    result = 0
    #b = fbin.read(1)
    b = next(value)
    print("pb_decode_varint32_eof %x" % b)
    
    if (b & 0x80 == 0):
        # Quick case, 1 byte value
        result = b;
    else:
        # Multibyte case 
        bitpos = 7;
        result = b & 0x7F;
        
        while True:
            #b = fbin.read(1)
            b = next(value)
            
            if not b:
                return None
            
            if (bitpos >= 32):
                # Note: The varint could have trailing 0x80 bytes, or 0xFF for negative. 
                if (bitpos < 63):
                    sign_extension = 0xFF
                else: 
                    sign_extension = 0x01                           
                
                if ( (b & 0x7F) != 0x00 and ((result >> 31) == 0 or b != sign_extension) ):
                    print("varint overflow");
                    return None
            else:
                result |= (b & 0x7F) << bitpos;
                print("result bitpos%d : %x" % (bitpos, result))
                
            bitpos = bitpos + 7;
            
            if (b & 0x80 == 0):
                break
        
        if (bitpos == 35 and (b & 0x70) != 0):
            # The last byte was at bitpos=28, so only bottom 4 bits fit. 
            print("varint overflow");
            
    return result            

def pb_decode_varint(value):
    bitpos =0
    result = 0
    
    while True:
        if (bitpos >= 64):
            print("varint overflow")
        
        b = next(value)
        print("next %x" % b)

        
        if not b:
            return None

        result |= (b & 0x7F) << bitpos
        bitpos = bitpos + 7
        print("result bitpos%d : %x" % (bitpos, result))
        
        if (b & 0x80):
            break
    
    return result;

def main():
    global memory_base 
    parser = argparse.ArgumentParser(description='Parses a PBNano file for the various message structures and writes it to a json file')

    parser.add_argument("--file", "-f", type=str, required=True, help="File which contains the pbnano compiled structure")
    parser.add_argument("--base", "-b", type=auto_int, required=False, help="base address where you found the pbnano definition")
    args = parser.parse_args()

    filename = args.file
    
    if not args.base:
        args.base = 0x3F420110

    memory_base = args.base
    print(hex(memory_base))
    
    fsize = os.path.getsize(filename)
    print("Unpacking %s size %x" %(filename, fsize))

    with open(filename,'rb') as fbin:
        fields = []
        jobject = []
        
        expand_subfield(fbin, fields, jobject)    
        
        with open('data.json', 'w', encoding='utf-8') as f:
            json.dump(jobject, f, ensure_ascii=False, indent=4)       


    # First Tag = 0xA
    # First wire type 0x6 =
    #inp = [0x0A, 0x06] 
    inp = [0x12, 0x19] 
    out = inp[0]
    #out=pb_decode_varint32_eof(iter(inp))
    tag = out >> 3;
    wire_type = out & 7;
    sinp = str(inp)
    print("in: %s out: %x tag:%x wire_type:%x" % (sinp, out, tag, wire_type))

"""
    # Tag 10, Wire type PB_LTYPE_SVARINT
    inp = [0x82, 0x1] 
    out=pb_decode_varint32_eof(iter(inp))
    tag = out >> 3;
    wire_type = out & 7;
    sinp = str(inp)
    print("in: %s out: %x tag:%x wire_type:%x" % (sinp, out, tag, wire_type))
    
    # Tag 4, Wire type PB_LTYPE_VARINT
    inp = [0x21, 0x08] 
    out = pb_decode_varint32_eof(iter(inp))
    tag = out >> 3;
    wire_type = out & 7;
    sinp = str(inp)
    print("in: %s out: %x tag:%x wire_type:%x" % (sinp, out, tag, wire_type))
    
    # Tag 0, Wire type PB_LTYPE_STRING
    inp = [0x06, 0x12]   
    out = pb_decode_varint32_eof(iter(inp))
    tag = out >> 3;
    wire_type = out & 7;
    sinp = str(inp)
    print("in: %s out: %x tag:%x wire_type:%x" % (sinp, out, tag, wire_type))
    
    
    inp = [0x0B, 0x57, 0x54, 0x32, 0x35, 0x47, 0x32, 0x2D, 0x30, 0x30, 0x30, 0x31] 
    out = pb_decode_varint32_eof(iter(inp))
    #out=pb_decode_varint(iter(inp))

    sinp = str(inp)
    print("in: %s out: %x" % (sinp, out))
"""                    

if __name__ == "__main__":
    main()
    
        
             