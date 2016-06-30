"""
Module that encapsilates all assembling and disassembling logic for Dash.
"""
import binascii
import os 
import platform
import subprocess
import string
import struct
import sys
import tempfile

# third party modules
import capstone
import keystone


class AssemblerError(Exception):
  """Generic exception class for Assembler Errors."""
  pass


class Assembler(object):
  """Class to encapsilate all assembling and disassembling logic."""
  def __init__(self):
    """
    Constructor.
    
    Returns:
      A new Assembler instance
    """
    # we default to x86 in 32-bit mode
    self.SetArchAndMode("X86", "32", "Little")
    
  def SetArchAndMode(self, arch, mode, endianess):
    """
    Set the architechture and mode to assemble and disassemble in
    """
    arches_and_modes = {("X86", "16", "Little"): ((keystone.KS_ARCH_X86, 
                                                   keystone.KS_MODE_16|keystone.KS_MODE_LITTLE_ENDIAN),
                                                  (capstone.CS_ARCH_X86,
                                                   capstone.CS_MODE_16|capstone.CS_MODE_LITTLE_ENDIAN)),
                        ("X86", "32", "Little"): ((keystone.KS_ARCH_X86, 
                                                  keystone.KS_MODE_32|keystone.KS_MODE_LITTLE_ENDIAN),
                                                  (capstone.CS_ARCH_X86,
                                                   capstone.CS_MODE_32|capstone.CS_MODE_LITTLE_ENDIAN)),
                        ("X86", "64", "Little"): ((keystone.KS_ARCH_X86, 
                                                  keystone.KS_MODE_64|keystone.KS_MODE_LITTLE_ENDIAN),
                                                  (capstone.CS_ARCH_X86,
                                                   capstone.CS_MODE_64|capstone.CS_MODE_LITTLE_ENDIAN)),
                        ("ARM", "16", "Big"): ((keystone.KS_ARCH_ARM, 
                                                keystone.KS_MODE_THUMB|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)),
                        ("ARM", "16", "Little"): ((keystone.KS_ARCH_ARM, 
                                                keystone.KS_MODE_THUMB|keystone.KS_MODE_LITTLE_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_THUMB|capstone.CS_MODE_LITTLE_ENDIAN)),
                        ("ARM", "32", "Big"): ((keystone.KS_ARCH_ARM, 
                                                keystone.KS_MODE_32|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)),
                        ("ARM", "32", "Little"): ((keystone.KS_ARCH_ARM, 
                                                keystone.KS_MODE_32|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)),
                        ("ARM64", "64", "Little"): ((keystone.KS_ARCH_ARM64, 
                                                keystone.KS_MODE_64|keystone.KS_MODE_LITTLE_ENDIAN),
                                                (capstone.CS_ARCH_ARM64,
                                                capstone.CS_MODE_64|capstone.CS_MODE_LITTLE_ENDIAN)),
                        ("MIPS", "32", "Big"): ((keystone.KS_ARCH_MIPS, 
                                                keystone.KS_MODE_32|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)),
                        ("MIPS", "32", "Little"): ((keystone.KS_ARCH_MIPS, 
                                                keystone.KS_MODE_32|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN))
                        }
    new_settings = arches_and_modes.get((arch, mode, endianess), None)
                                                              
    if not new_settings:
      # leave the settings as is
      return
    
    self.asm_arch = new_settings[0][0]
    self.asm_mode = new_settings[0][1]
    self.disasm_arch = new_settings[1][0]
    self.disasm_mode = new_settings[1][1]
    self.assembler = keystone.Ks(self.asm_arch, self.asm_mode)
    self.disassembler = capstone.Cs(self.disasm_arch, self.disasm_mode)
    

  def IsADataDefinitionInstruction(self, mnemonic):
    """
    Is this instruction a db, dw, dd, or dq instruction? 
    
    Args:
      mnemonic: a string mnemonic
      
    Returns:
      True if it's an instruction that defines data. False otherwise.
    """
    for inst in ['DB', 'DW', 'DD', 'DQ']:
      if mnemonic.upper().strip().startswith(inst):
        return True
    return False
  
  def Assemble(self, index, store):
    """Assemble the mnemonics provided in the store.
    
    This will assemble all instructions before and after in order to support 
    labels
    
    Args:
      index: an integer describing the currently selected row in the table.
      store: An AssemblyStore instance
    
    Returns:
      N / A
      
    Side Effects:
      Updates the assembly store at the given path (row index) 
    """
    store.ClearErrors();
    cur_addr = None
    for row in store.GetRowsIterator():
      if not row.in_use:
        continue
      # check if this row contains a label and adjust the mnemonic (TODO)
      if not cur_addr:
        cur_addr = row.address
        
      try:
        encoded_bytes, inst_count  = self.assembler.asm(row.mnemonic,
                                                        addr=cur_addr)
        opcode_str = "".join(["%02x" % byte for byte in encoded_bytes])
        row.opcode = binascii.unhexlify(opcode_str)
        row.address = cur_addr
        cur_addr += len(encoded_bytes)
        store.UpdateRow(row.index, row)
      except Exception as exc:
        print str(exc)
        store.SetErrorAtIndex(row.index)
        break
    return


  def Disassemble(self, index, store):
    """
    Disassembles the instruction given the opcode string taken from a row at
    the index provided.
    
    Args:
      index: an integer row index in the AssemblyStore
      store: The AssemblyStore instance
      
    Returns:
      N / A
      
    Side Effects:
      Updates the AssemblyStore row specified by the index.
    """
    row = store.GetRow(index)
    # disassemble and set in the store
    instructions = list(self.disassembler.disasm(row.opcode, row.address))
    
    if instructions:
      row.opcode = str(instructions[0].bytes)
      row.SetMnemonic("%s %s" % (instructions[0].mnemonic, instructions[0].op_str))
      
      store.UpdateRow(row.index, row)
      
      if len(instructions) > 1:
        for i in xrange(1, len(instructions)):
          store.CreateRowFromCapstoneInst(row.index + i, instructions[i])
