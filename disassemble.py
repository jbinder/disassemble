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

from PyQt4.QtCore import Qt, SIGNAL
from PyQt4.QtGui import QWidget, QTextCursor, QTextEdit, QTextOption, QScrollBar, QAbstractSlider, QHBoxLayout, QSplitter, QFont

from elfdisassembler import ElfDisassembler

# This module is based on the textviewer module. The custom scrollbar is used because of performance issues on large binaries.

class TextEdit(QTextEdit):
  def __init__(self, disassembly):
    QTextEdit.__init__(self)
    self.disassembly = disassembly
    self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
    self.setReadOnly(1)
    self.setWordWrapMode(QTextOption.NoWrap)
    self.setFont(QFont("Courier New"))

  def wheelEvent(self, event):
    scroll = self.disassembly.scroll
    v = scroll.value()
    if event.delta() > 0:
      trig = v - 5
      if trig >= scroll.min:
        self.disassembly.read(trig)
        scroll.setValue(trig)
    else:
      trig = v + 5
      if trig < scroll.max:
        self.disassembly.read(trig)
        scroll.setValue(trig)

class Scroll(QScrollBar):
    def __init__(self, parent):
      QScrollBar.__init__(self, parent)
      self.disassembly = parent
      self.init()
      self.initCallBacks()
      self.setValues()

    def init(self):
      self.min = 0
      self.single = 1
      self.page = 32
      self.max = self.disassembly.lines - 1

    def initCallBacks(self):
      self.connect(self, SIGNAL("sliderMoved(int)"), self.moved) 
      self.connect(self, SIGNAL("actionTriggered(int)"), self.triggered) 

    def setValues(self):
      self.setMinimum(self.min)
      self.setMaximum(self.max)
      self.setSingleStep(self.single)
      self.setPageStep(self.page)
      self.setRange(self.min, self.max)

    def triggered(self, action):
      if action == QAbstractSlider.SliderSingleStepAdd:
        trig = self.value() + 1
        if trig <= self.max:
          self.disassembly.read(trig)
      elif action == QAbstractSlider.SliderSingleStepSub:
        trig = self.value() - 1
        if trig >= self.min:
          self.disassembly.read(trig)
      elif action == QAbstractSlider.SliderPageStepSub:
        trig = self.value() - 5
        if trig >= self.min:
          self.disassembly.read(trig)
      elif action == QAbstractSlider.SliderPageStepAdd:
        trig = self.value() + 5
        if trig <= self.max:
          self.disassembly.read(trig)

    def moved(self, value):
      if value == self.max:
        value -= 5
      self.disassembly.read(value)

class Disassemble(QSplitter, Script):
  def __init__(self):
    Script.__init__(self, "disassemble")

  def start(self, args):
    self.stateinfo = "started..."
    try:
      self.node = args['file'].value()
    except:
      pass

  def g_display(self): 
    QSplitter.__init__(self) 
    self.offsets = self.linecount()
    self.initShape() 
    self.read(0) 
 
  def initShape(self): 
    self.hbox = QHBoxLayout() 
    self.hbox.setContentsMargins(0, 0, 0, 0) 
 
    textAreaWidget = QWidget() 
 
    self.scroll = Scroll(self) 
    self.text = TextEdit(self) 
 
    self.hbox.addWidget(self.text) 
    self.hbox.addWidget(self.scroll) 
 
    textAreaWidget.setLayout(self.hbox) 
 
    self.addWidget(textAreaWidget)  
    self.setStretchFactor(0, 0)   
    self.setStretchFactor(1, 1) 

  def read(self, line):
    self.text.clear()
    self.text.textCursor().insertText('\n'.join(self.getDisassembly()[line:line+200])) # TODO: get rid of the magic value!
    self.text.moveCursor(QTextCursor.Start)

  def getDisassembly(self):
    if hasattr(self, "disassembly"):
      return self.disassembly
    vfile = self.node.open()
    content = vfile.read()
    vfile.close()
    elfDisassembler = ElfDisassembler()
    self.disassembly = ("%s - " % (self.node.name()) + elfDisassembler.disassemble(content)).split('\n')
    return self.disassembly
 
  def linecount(self):
    offsets = [0]
    disassembly = self.getDisassembly()
    indices = [i for i, x in enumerate(disassembly)]
    offsets.extend(indices)
    self.lines = len(offsets)
    return offsets

  def updateWidget(self):
    pass

  def c_display(self):
    pass

class disassemble(Module):
  """This module shows the disassembly of a binary"""
  def __init__(self):
    Module.__init__(self, "disassemble", Disassemble)
    self.conf.addArgument({"name": "file",
                           "description": "file to disassemble",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.flags = ["gui"]
    self.tags = "Viewers"

