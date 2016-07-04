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

#constants
LITTLE_ENDIAN    = 0
BIG_ENDIAN       = 1
X86_16           = 0
X86_32           = 1
X86_64           = 2
ARM_16           = 3 #THUMB MODE
ARM_32           = 4
ARM_64           = 5
MIPS_32          = 6



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
    self.SetArchAndMode(X86_32, LITTLE_ENDIAN)
    
  def SetArchAndMode(self, arch_mode, endianess):
    """
    Set the architechture and mode to assemble and disassemble in
    """
    arches_and_modes = {(X86_16, LITTLE_ENDIAN): ((keystone.KS_ARCH_X86, 
                                                   keystone.KS_MODE_16|keystone.KS_MODE_LITTLE_ENDIAN),
                                                  (capstone.CS_ARCH_X86,
                                                   capstone.CS_MODE_16|capstone.CS_MODE_LITTLE_ENDIAN)),
                        (X86_32, LITTLE_ENDIAN): ((keystone.KS_ARCH_X86, 
                                                  keystone.KS_MODE_32|keystone.KS_MODE_LITTLE_ENDIAN),
                                                  (capstone.CS_ARCH_X86,
                                                   capstone.CS_MODE_32|capstone.CS_MODE_LITTLE_ENDIAN)),
                        (X86_64, LITTLE_ENDIAN): ((keystone.KS_ARCH_X86, 
                                                  keystone.KS_MODE_64|keystone.KS_MODE_LITTLE_ENDIAN),
                                                  (capstone.CS_ARCH_X86,
                                                   capstone.CS_MODE_64|capstone.CS_MODE_LITTLE_ENDIAN)),
                        (ARM_16, BIG_ENDIAN): ((keystone.KS_ARCH_ARM, 
                                                keystone.KS_MODE_THUMB|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)),
                        (ARM_16, LITTLE_ENDIAN): ((keystone.KS_ARCH_ARM, 
                                                keystone.KS_MODE_THUMB|keystone.KS_MODE_LITTLE_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_THUMB|capstone.CS_MODE_LITTLE_ENDIAN)),
                        (ARM_32,BIG_ENDIAN): ((keystone.KS_ARCH_ARM, 
                                                keystone.KS_MODE_32|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)),
                        (ARM_32, LITTLE_ENDIAN): ((keystone.KS_ARCH_ARM, 
                                                keystone.KS_MODE_32|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)),
                        (ARM_64, LITTLE_ENDIAN): ((keystone.KS_ARCH_ARM64, 
                                                keystone.KS_MODE_64|keystone.KS_MODE_LITTLE_ENDIAN),
                                                (capstone.CS_ARCH_ARM64,
                                                capstone.CS_MODE_64|capstone.CS_MODE_LITTLE_ENDIAN)),
                        (MIPS_32, BIG_ENDIAN): ((keystone.KS_ARCH_MIPS, 
                                                keystone.KS_MODE_32|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN)),
                        (MIPS_32, LITTLE_ENDIAN): ((keystone.KS_ARCH_MIPS, 
                                                keystone.KS_MODE_32|keystone.KS_MODE_BIG_ENDIAN),
                                                (capstone.CS_ARCH_ARM,
                                                capstone.CS_MODE_32|capstone.CS_MODE_BIG_ENDIAN))
                        }
    new_settings = arches_and_modes.get((arch_mode, endianess), None)
                                                              
    if not new_settings:
      # leave the settings as is
      return
    self.arch_mode =  arch_mode
    self.endianess = endianess
    
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
  
  def RelaxInstructions(self, store, list_of_fixups, labels):
    """
    Relax assembly instructions as necessary.
    
    Args:
      store: An AssemblyStore instance.
      list_of_fixups: a dictionary of instructions and their indices that need to be
                      adjusted.
      labels: A dictionary of label names to addresses.
    
    Returns:
      N / A
    
    Side Effects:
      This will adjust the assembled instructions using wider versions
      when a labels address is beyond the range of the short forms 
      (e.g. jumps and calls on x86)
    """
    done_relaxing = False
    
    #last rounds label addresses
    last_rounds_label_addresses = labels
    
    while not done_relaxing:
      for row in store.GetRowsIterator():
        if row.index not in list_of_fixups:
          continue
        
        mnemonic, label = list_of_fixups[row.index]
        label_addr_st = hex(labels[label]).replace('L', '')
        mnemonic = mnemonic.replace(label, label_addr_st)
        
        try:
          encoded_bytes, inst_count  = self.assembler.asm(mnemonic,
                                                          addr=row.address)
          opcode_str = "".join(["%02x" % byte for byte in encoded_bytes])
          row.opcode = binascii.unhexlify(opcode_str)
          store.UpdateRow(row.index, row)
          # scan to make sure we updated all of the symbols addresses
          for row in store.GetRowsIterator():
            if row.label != '':
              labels[row.label] = row.address
          
        except Exception as exc:
          # TODO: replace this with logging
          print str(exc)
          store.SetErrorAtIndex(row.index)
          break
        
      # collect the labels update check if 
      for row in store.GetRowsIterator():
        if row.label != '':
          labels[row.label.upper()] = row.address
      # check to see if any labels differ at all if yes then continue relaxing
      if labels == last_rounds_label_addresses:
        done_relaxing = True
      else:
        last_rounds_label_addresses = labels
  
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
    label_fixup_rows = {}
    known_label_addresses = {}
    
    for row in store.GetRowsIterator():
      if not row.in_use:
        continue
      
      if not cur_addr:
        cur_addr = row.address
       
      if row.label:
        known_label_addresses[row.label.upper()] = cur_addr
        
      try:
        # check if this row contains a label and adjust the mnemonic we're assembling
        asm_label = store.ContainsLabel(row.mnemonic)
        if asm_label:
          if asm_label in known_label_addresses:
            asm_label_addr_str = hex(known_label_addresses[asm_label]).replace('L', '')
            mnemonic = row.mnemonic.replace(asm_label, asm_label_addr_str)
          else:
            # store the original mnemonic replacing the new one with
            label_fixup_rows[row.index] = (row.mnemonic, asm_label)
            mnemonic = row.mnemonic.replace(asm_label, hex(row.address + 1).replace('L', ''))
        else:
          mnemonic = row.mnemonic
        
        encoded_bytes, inst_count  = self.assembler.asm(mnemonic,
                                                        addr=cur_addr)
        opcode_str = "".join(["%02x" % byte for byte in encoded_bytes])
        row.opcode = binascii.unhexlify(opcode_str)
        row.address = cur_addr
        cur_addr += len(encoded_bytes)
        store.UpdateRow(row.index, row)
      except Exception as exc:
        # TODO: replace this with logging
        print str(exc)
        store.SetErrorAtIndex(row.index)
        break
      
    # this is a quick and dirty means of dealing with label fixups and should
    # be arch dependent as we want to be able to support relaxation.
    if label_fixup_rows and known_label_addresses:
      self.RelaxInstructions(store, label_fixup_rows, known_label_addresses)
      
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
    else:
      store.SetErrorAtIndex(index)

