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
import darm
from elfesteem import *
from miasm.arch.arm_arch import arm_mn
from miasm.core.bin_stream import bin_stream
from miasm.core import asmbloc
from StringIO import StringIO
import os

class ElfDisassembler:
    """ Disassembles ELF files """

    elfClassNames = {0:'None', 1:'x32', 2:'x64'}
    elfClassEnum = {0:Decode32Bits, 1:Decode32Bits, 2:Decode64Bits}

    def disassemble(self, elfFileContent): 
        """ Returns the disassembled code as text
            if provided by the content of an elf file as string """
        elf = self.__createElf(elfFileContent)
        self.elfClass = self.__class__.elfClassEnum[elf.header.elfclass]
        result = self.__getElfInfo(elf) + "\n"
        if (self.__getMachine(elf.header) != "EM_ARM"):
            result += self.__disassembleX32X64Elf(elf)
        else:
            result += "\n" + self.__disassembleArmElf(elfFileContent)
        return result

    def __disassembleArmElf(self, elfFileContent):
        e = elf_init.ELF(elfFileContent)
        return (self.__disassembleArm(e.virt))

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

    def __disassembleArm(self, content):
        in_str = bin_stream(content)
        job_done = set()
        symbol_pool = asmbloc.asm_symbol_pool()
        all_bloc = asmbloc.dis_bloc_all(arm_mn, in_str, 0, job_done, symbol_pool, follow_call = False, lines_wd = 20)
        lines = []
        for bloc in all_bloc:
            lines.append(str(bloc))
        return ('\n'.join(lines))
 
