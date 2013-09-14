disassemble
===========

Module for the Digital Forensics Framework which adds basic disassemble capabilities.
At the moment x86 and AMD64 ELF binaries are supported.
ARM disassembling is tried only if the above fails.


Requirements
------------

*   Digital Forensics Framework 1.3.0 (http://www.digital-forensic.org/), GNU GPL v2
*   diStorm 3.3 (https://code.google.com/p/distorm/), GNU GPL v3
*   PyDevTools r42 (http://code.google.com/p/pydevtools/), BSD New
*   Miasm 0.1 (https://code.google.com/p/smiasm/), GNU GPL v2


Install
-------

*   get the DFF source: http://wiki.digital-forensic.org/index.php/Installation
*   install diStorm, PyDevTools and Miasm
*   checkout disassemble into [dff-root-dir]/dff/modules/viewer/
*   add `add_subdirectory (disassemble)` to [dff-root-dir]/dff/modules/viewer/CMakeLists.txt
*   build DFF: http://wiki.digital-forensic.org/index.php/Installation


History
-------

tbd

