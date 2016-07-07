"""
assembler_tests.py: unit tests for the app/assembler.py module
"""
import pytest

import app.assembler as assembler
import app.assembly_store as assembly_store

@pytest.fixture
def asm_store():
  return assembly_store.AssemblyStore()

@pytest.fixture
def x86_16_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.X86_16, 
                                              assembler.LITTLE_ENDIAN)
@pytest.fixture
def x86_32_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.X86_32, 
                                              assembler.LITTLE_ENDIAN)
@pytest.fixture
def x86_64_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.X86_32, 
                                              assembler.LITTLE_ENDIAN)
@pytest.fixture
def thumb_le_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.ARM_16, 
                                              assembler.LITTLE_ENDIAN)
@pytest.fixture
def thumb_be_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.ARM_16, 
                                              assembler.BIG_ENDIAN)

@pytest.fixture
def arm_le_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.ARM_32, 
                                              assembler.LITTLE_ENDIAN)
@pytest.fixture
def arm_be_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.ARM_32, 
                                              assembler.BIG_ENDIAN)

@pytest.fixture
def arm64_le_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.ARM_64, 
                                              assembler.LITTLE_ENDIAN)

@pytest.fixture
def mips_le_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.MIPS_32, 
                                              assembler.LITTLE_ENDIAN)
@pytest.fixture
def mips_be_assembler():
  return assembler.Assembler().SetArchAndMode(assembler.MIPS_32, 
                                              assembler.BIG_ENDIAN)




def InsertInstruction(asm_store, index, mnemonic='', label='', address=0,
                      opcode='', comment=''):
  """
  Create a Row Data object for an instruction.
  """
  row = assembly_store.RowData(0, label, address, opcode, mnemonic, 
                              comment)
  asm_store.InsertRowAt(index, row)
  
  
def assembly_test_helper(store, asm, mnemonics):
  """
  Test that we can assemble some instructions given mnemonics and a
  configured store and assembler.
  """
  store.Reset()
  
  for i, mnemonic in enumerate(mnemonics):
    InsertInstruction(store, i, mnemonic)
    
  asm.Assemble(store)
  
  # check that we assembled correctly and that the opcodes are correct
  for row in store.GetRows():
      assert row.mnemonic == mnemonics[row.index], \
             "Incorrect mnemonic from assembling %s" % \
             insts_to_insert[row.index]
      
      
def test_x86RealModeAssembly(asm_store):
  """
  Test that we can assemble some basic x86 16-bit instructions. 
  """
  insts = ["xor ax, ax", "90", "add cl, ax"]
  # check that we assembled correctly and that the opcodes are correct
  assembly_test_helper(asm_store, x86_16_assembler(), insts)

        
def test_X86ProtectedModeAssembly(asm_store):
  """
  Test that we can assemble some basic x86 32-bit instructions. 
  
  This is the default mode that Dash runs in.
  """
  insts = ["xor eax, eax", "nop", "add ecx, edx"]
      
  # check that we assembled correctly and that the opcodes are correct
  assembly_test_helper(asm_store, x86_32_assembler(), insts)
  
def test_X86_64LongModeAssembly(asm_store):
  insts = ["add rcx, rdx", "sub rcx, rbx", "mov r8, r9"]
   # check that we assembled correctly and that the opcodes are correct
  assembly_test_helper(asm_store, x86_64_assembler(), insts)
  
def test_thumbAssembly(asm_store):
  insts = ["mov r0, r1", "add R1, 0x7", "bx r8"]
  assembly_test_helper(asm_store, thumb_le_assembler(), insts)
  assembly_test_helper(asm_store, thumb_be_assembler(), insts)

def test_ARMAssembly(asm_store):
  insts = ["mov r0, r1", "add R1, R5, 0x7", "blx r8"]
  assembly_test_helper(asm_store, arm_le_assembler(), insts)
  assembly_test_helper(asm_store, arm_be_assembler(), insts)
  
def test_ARM64Assembly(asm_store):
  insts = ["MOV W0, 0x1", "STR W8, [SP]", "MADD X8, X0, X0, XZR"]
  assembly_test_helper(asm_store, arm64_le_assembler(), insts)
  
def test_MIPSAssembly(asm_store):
  insts = ["and $6, $7, $8", "j 0x2000"]
  assembly_test_helper(asm_store, mips_le_assembler(), insts)
  assembly_test_helper(asm_store, mips_be_assembler(), insts)

