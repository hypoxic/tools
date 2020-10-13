"""
Movt's tend to be discontinuous in the latest arm compilers. This script puts them
back together. Based upon https://github.com/xyzz/vita-ida-physdump/blob/master/vita_phys_dump.py


Revision history
=========================
v1.0 - initial version
v1.1 - Added this comment years after I started using this, not sure the changes - Trunk / Hypoxic

"""



try:
    import idaapi
    import idc
    import idautils
    import ida_offset
    import ida_auto, ida_kernwin, ida_diskio
    ida = True
except:
    ida = False


def add_xrefs(addr, end=idc.BADADDR):
    """
        https://github.com/xyzz/vita-ida-physdump/blob/master/vita_phys_dump.py
        Searches for MOV / MOVT pair, probably separated by few instructions,
        and adds xrefs to things that look like addresses
    """    
    while addr < end and addr != BADADDR:
        addr = idc.NextHead(addr)
        if idc.GetMnem(addr) in ["MOV", "MOVW"]:
            reg = idc.GetOpnd(addr, 0)
            if idc.GetOpnd(addr, 1)[0] != "#":
                continue
            val = idc.GetOperandValue(addr, 1)
            found = False
            next_addr = addr
            for x in range(16):
                next_addr = idc.NextHead(next_addr)
                if idc.GetMnem(next_addr) in ["B", "BX"]:
                    break
                # TODO: we could handle a lot more situations if we follow branches, but it's getting complicated
                # if there's a function call and our register is scratch, it will probably get corrupted, bail out
                if idc.GetMnem(next_addr) in ["BL", "BLX"] and reg in ["R0", "R1", "R2", "R3"]:
                    break
                # if we see a MOVT, do the match!
                if idc.GetMnem(next_addr) in ["MOVT", "MOVT.W"] and idc.GetOpnd(next_addr, 0) == reg:
                    if idc.GetOpnd(next_addr, 1)[0] == "#":
                        found = True
                        val += idc.GetOperandValue(next_addr, 1) * (2 ** 16)
                    break
                # if we see something other than MOVT doing something to the register, bail out
                if idc.GetOpnd(next_addr, 0) == reg or idc.GetOpnd(next_addr, 1) == reg:
                    break
            if val & 0xFFFF0000 == 0:
                continue
            if found:
                # pair of MOV/MOVT
                try:
                    idc.OpOffEx(addr, 1, idc.REF_LOW16, val, 0, 0)
                    idc.OpOffEx(next_addr, 1, idc.REF_HIGH16, val, 0, 0)
                except:
                    print "Failed xref @ %x next_addr %x val %x" % (addr, next_addr, val)
            else:
                # a single MOV instruction
                try:
                    idc.OpOff(addr, 1, 0)
                except:
                    print "Failed xref at addr %x" % (addr)
                    


# -----------------------------------------------------------------------
def main():
    for ea in idautils.Segments():
        if idc.SegName(ea) == ".text":
            start = idc.SegStart(ea)
            end = idc.SegEnd(ea)
            print '.text %x-%x'%(start, end)
            add_xrefs(start,end)
    return 1

if ida:
    print "Fixing discontinuos moves"
    main()
