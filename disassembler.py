# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# 
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
# 
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Johannes Binder <j.binder.x@gmail.com>

from distorm3 import Decode, Decode16Bits, Decode32Bits, Decode64Bits
from bintools.elf import ELF
from bintools.elf import MACHINE
from elfesteem import *
from miasm.tools.pe_helper import *
from miasm.arch.arm_arch import arm_mn
from miasm.arch.ia32_arch import x86_mn
from miasm.core.bin_stream import bin_stream
from miasm.core import asmbloc
from StringIO import StringIO
import os

class Disassembler:
    """ Disassembles binary files """

    elfClassNames = {0:'None', 1:'x32', 2:'x64'}
    elfClassEnum = {0:Decode32Bits, 1:Decode32Bits, 2:Decode64Bits}

    def disassemble(self, data): 
        """ Returns the disassembled code as text
            if provided by the content of an elf file as string """
        if data.startswith("MZ"):
            print "disassembling PE..."
            result = self.__disassemblePE(data)
        elif data.startswith("\x7fELF"):
            print "disassembling ELF..."
            result = self.__disassembleElf(data)
        else:
            print "disassembling raw binary, fallback..."
            result = self.__disassembleRaw(data)
        return result

    def __disassembleElf(self, data):
        elf = self.__createElf(data)
        self.elfClass = self.__class__.elfClassEnum[elf.header.elfclass]
        result = self.__getElfInfo(elf) + "\n"
        if (self.__getMachine(elf.header) != "EM_ARM"):
            result += self.__disassembleX32X64Elf(elf)
        else:
            result += "\n" + self.__disassembleArmElf(data)
        return result

    def __disassemblePE(self, data):
        e = pe_init.PE(data)
        header = self.__getPeInfo(e)
        address = e.rva2virt(e.Opthdr.AddressOfEntryPoint)
        dll_dyn_funcs = get_import_address(e)
        return header + (self.__disassembleMiasm(e.virt, address, x86_mn, dll_dyn_funcs))

    def __getPeInfo(self, e):
        if isinstance(e.Opthdr, pe.Opthdr32):
            arch = "x32"
        elif isinstance(e.Opthdr, pe.Opthdr64):
            arch = "x64"
        else:
            arch = "unknown"
        return "PE format: %s\n\n" % (arch)

    def __disassembleRaw(self, data):
        header = "Raw\n\n" # TODO: get binary info
        address = 0
        return header + (self.__disassembleMiasm(data, address, x86_mn, {}))

    def __disassembleArmElf(self, data):
        e = elf_init.ELF(data)
        address = e.Ehdr.entry
        dll_dyn_funcs = get_import_address_elf(e)
        return (self.__disassembleMiasm(e.virt, address, arm_mn, dll_dyn_funcs))

    def __disassembleX32X64Elf(self, elf):
        result = []
        for header in elf.sect_headers:
            if header.type != 1 or header.flags != 6: # see http://code.google.com/p/pydevtools/source/browse/trunk/bintools/elf/structs.py for a list of properties
                continue
            result.append(self.__getDisassemble(header))
        return '\n'.join(result)

    def __getElfInfo(self, elf):
        return "ELF format: %s, %s" % (self.__class__.elfClassNames[elf.header.elfclass], self.__getMachine(elf.header))

    def __getMachine(self, header):
        return MACHINE.dict[header.machine]
 
    def __createElf(self, content):
        io2 = StringIO()
        io2.write(content)
        io2.seek(0, os.SEEK_SET)
        return ELF(io2)

    def __getDisassemble(self, sectionHeader):
        rawLines = Decode(sectionHeader.addr, sectionHeader.data, self.elfClass)
        lines = []
        lines.append("\n%s (0x%08x):" % (sectionHeader.name, sectionHeader.addr))
        for rawLine in rawLines:
            lines.append("0x%08x (%02x) %-20s %s" % (rawLine[0],  rawLine[1],  rawLine[3],  rawLine[2]))
        return ('\n'.join(lines))

    def __disassembleMiasm(self, data, address, mn, dll_dyn_funcs):
        in_str = bin_stream(data)
        job_done = set()
        symbol_pool = asmbloc.asm_symbol_pool()
        for (n,f), ads in dll_dyn_funcs.items():
            for ad in ads:
                l  = symbol_pool.getby_name_create("%s_%s"%(n, f))
                l.offset = ad
                symbol_pool.s_offset[l.offset] = l

        all_bloc = asmbloc.dis_bloc_all(mn, in_str, address, job_done, symbol_pool, follow_call = True, lines_wd = 60)
        lines = []
        for bloc in all_bloc:
            lines.append(str(bloc))
        return ('\n'.join(lines))
 
