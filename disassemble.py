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

__dff_module_disassemble_version__ = "1.0.0"

from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Argument, typeId

class Disassemble(Script):
  def __init__(self):
    Script.__init__(self, "disassemble")

  def start(self, args):
    pass

class disassemble(Module):
  """This module shows the disassembly of a binary"""
  def __init__(self):
    Module.__init__(self, "disassemble", Disassemble)
    self.conf.addArgument({"name": "file",
                           "description": "file to disassemble",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.flags = ["single"]
    self.tags = "Viewers"

