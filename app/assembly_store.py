"""
assembly_store.py: classes and logic for generating and storing the state of
                   the program.

Author: Pete Markowsky <peterm@vodun.org>
"""
import binascii
import cPickle

X86 = 'x86'
X64 = 'x64'
ARM = 'arm'
ARM64 = 'arm64'
MIPS = 'mips'


class RowData(object):
    """
    Object representing an individual row of assembly.
    """
    def __init__(self, offset, label, address, opcode, mnemonic, comment,
                 index=0, in_use=False, stack_delta=0):
        self.offset = offset
        self.label = label
        self.address = address
        self.opcode = opcode
        self.mnemonic = mnemonic
        self.comment = comment
        self.index = index
        self.in_use = in_use
        self.error = False
        self.targets = [0]
        self.is_a_data_defintion_inst = False
        self.is_branch_or_call = False
        self.stack_delta = stack_delta

    def ToDict(self):
        """
        Return a row as a dict for conversion to JSON
        """
        error_st = 0
        if self.error:
            error_st = 1

        return {'offset': self.offset,
                'label': self.label,
                'address': self.DisplayAddress(),
                'opcode': self.DisplayOpcode(),
                'mnemonic': self.mnemonic,
                'comment': self.comment,
                'index': self.index,
                'error': error_st,
                'in_use': self.in_use,
                'targets': self.targets,
                'is_a_data_definition_inst': self.is_a_data_defintion_inst,
                'is_a_branch_or_call': self.is_branch_or_call}

    def SetComment(self, comment):
        """
        Set a row's comment field if possible (this will fail with non-ascii).
        
        Args:
          comment: A string comment this expects to be utf-8 that can decode
                   as ascii.
          
        Returns:
          N / A
        """
        try:
            self.comment = comment.encode('ascii')
        except UnicodeDecodeError:
            pass

    def SetLabel(self, label):
        """
        Set a RowData's label field if possible (this will fail with non-ascii).
        
        Args:
          label: A string label this expects utf-8 that can be decoded as ascii
          
        Returns:
           N / A
        """
        try:
            self.label = label.encode('ascii').upper()
        except UnicodeDecodeError:
            pass

    def SetAddress(self, address):
        """
        Set the address from a string.
        """
        try:
            if address.startswith('0x'):
                self.address = int(address, 16)
            else:
                self.address = int(address)
        except:
            pass

    def DisplayAddress(self):
        """
        Format an address as a hexadecimal string for display.
        """
        return hex(self.address).replace('L', '')

    def SetOpcode(self, hex_str):
        """
        Set the opcodes for the row and make sure that the string is a proper
        hex string.
        """
        try:
            self.opcode = binascii.unhexlify(hex_str.replace(' ', ''))
            self.in_use = True
        except:
            self.in_use = False
            self.opcode = hex_str
            self.mnemonic = '<INVALID OPCODE SUPPLIED>'
            self.error = True

    def SetMnemonic(self, mnemonic):
        """
        Set the mnemonic of the row.

        Args:
          mnemonic: a string

        Returns:
          N / A
        """
        if mnemonic == '':
            self.opcodes = ''
            self.in_use = False
            return

        self.mnemonic = mnemonic

        # this is a hack find a better way to do this
        normalized_mnemonic = mnemonic.lower().strip()
        # FIXME -- this is hard coded for x86/x64 specific
        if normalized_mnemonic.startswith('j') or \
           normalized_mnemonic.startswith('call'):
            self.is_branch_or_call = True
        else:
            self.is_branch_or_call = False

        if normalized_mnemonic.split()[0] in ('db', 'dw', 'dd', 'dq'):
            self.is_a_data_defintion_inst = True
        else:
            self.is_a_data_defintion_inst = False
        # fix capitalization
        # TODO better formatting
        new_mnemonic = self.mnemonic.split()
        self.mnemonic = ''
        self.mnemonic += new_mnemonic[0].upper() + ' ' + \
            ''.join(new_mnemonic[1:])
        self.in_use = True

    def DisplayOpcode(self):
        """
        Format the opcode string for display

        Args:
          N / A

        Returns:
          a string of hex bytes separated with spaces
        """
        original_str = binascii.hexlify(self.opcode)
        hex_str = ''

        for i in xrange(len(original_str)):
            hex_str += original_str[i]
            if i % 2 == 1:
                hex_str += ' '

        return hex_str.upper().strip()


class AssemblyStoreError(Exception):
    pass


class AssemblyStore(object):
    """
    This class holds all of the state information for the current assembler
    session
    """
    _instance = None

    def __new__(cls, *args, **kwargs):
        """
        Override the new operator so as to keept the assembly store a
        singleton.
        """
        if not cls._instance:
            cls._instance = super(AssemblyStore, cls).__new__(cls, *args,
                                                              **kwargs)
        return cls._instance

    def __init__(self):
        self.bits = 32
        self.display_labels = True
        self.rows = []
        self.filter_bytes = ""
        self.cfg = None
        self.labels = set([])

        # add 20 empty rows by default.
        self.AddRows(20)

    def DeepCopyRow(self, index):
        """
        Fast deep copy of a row using cPickle
        """
        if index < 0 or index >= len(self.rows):
            raise AssemblyStoreError("Invalid row index %s" % str(index))

        row = self.rows[index]
        return cPickle.loads(cPickle.dumps(row, -1))

    def SetBits(self, bits):
        """
        Set the operating mode  e.g. 16, 32, or 64

        Args:
          bits: an integer that's either 16,32, or 64

        Returns:
          True if the value was set False otherwise.
        """
        if bits in (16, 32, 64):
            self.bits = bits
            return True
        else:
            return False

    def SetEndianess(self, little=True):
        self.little_endian = little

    def Reset(self):
        """
        Reset the AssemblyStore's state to an empty AssemblyStore.
        """
        self.cfg = None
        self.rows = []

    def CreateRowFromCapstoneInst(self, index, inst):
        """
        Create rows from a distorm3 instruction instance.

        Args:
          index: a positive integer
          inst: a capstone.CsInsn instance

        Returns:
          N / A
        """
        mnemonic = "%s %s" % (inst.mnemonic.upper(), inst.op_str)
        row = RowData(0, '', inst.address, str(inst.bytes), mnemonic, '',
                      index, in_use=True)
        # check to see if the instruction is a branch instruction else set
        # it's target to address plus length of instructionBytes
        self.InsertRowAt(index, row)
        self.UpdateOffsetsAndAddresses()

    def InsertRowAt(self, index, row):
        """
        Insert a new row at the index and update the offsets and addresses
        """
        self.rows.insert(index, row)
        self.rows[index].index = index

        for i in xrange(index + 1, len(self.rows)):
            self.rows[i].index = i

        self.UpdateOffsetsAndAddresses()

    def AddRows(self, num_rows, starting_index=None):
        """
        Append num_rows empty rows to the store.
        """
        if not starting_index:
            starting_index = len(self.rows)

        for i in xrange(num_rows):
            self.rows.append(RowData(0, '', 0, '', '', '', starting_index))
            starting_index += 1

    def ContainsLabel(self, row_asm):
        """
        Check if this row contains a label as a target

        Args:
          row_asm: the string mnemonic of an instruction in a row.

        Returns:
          The label if it is in the row_asm, None otherwise.
        """
        for label in self.labels:
            if label in row_asm:
                return label
        return None

    def UpdateRow(self, i, new_row):
        """
        Update a row at a given offset
        """
        self.rows[i] = new_row
        if new_row.label != '' and new_row.label not in self.labels:
            self.labels.add(new_row.label)
        # update offsets and addresses
        self.UpdateOffsetsAndAddresses()

    def DeleteRow(self, index):
        """
        Delete a row in the assembly store.

        Args:
          index: a positive integer index of the row data to delete.

        Returns:
          N / A
        """
        self.rows.pop(index)

        # update the row indices
        for i in xrange(0, len(self.rows)):
            self.rows[i].index = i

        self.UpdateOffsetsAndAddresses()

    def UpdateOffsetsAndAddresses(self):
        """
        Update all of the offsets and addresses after altering row data.

        Args:
          N / A

        Returns:
          N / A

        Side Effects:
          Updates the offsets and addresses of each row in the store.
        """
        self.rows[0].offset = 0
        next_address = None
        next_offset = 0

        # update offsets and addresses
        for i in xrange(0, len(self.rows)):
            if not self.rows[i].in_use:
                continue

            if not next_address:
                next_address = self.rows[i].address + len(self.rows[i].opcode)
                next_offset = self.rows[i].offset + len(self.rows[i].opcode)
                continue

            self.rows[i].address = next_address
            self.rows[i].offset = next_offset
            next_address += len(self.rows[i].opcode)
            next_offset += len(self.rows[i].opcode)

    def ClearErrors(self):
        """
        Clear all errors from rows.
        """
        for i in xrange(len(self.rows)):
            self.rows[i].error = False

    def SetErrorAtIndex(self, index):
        """
        Mark a row as being in error.
        """
        self.rows[index].error = True

    def GetRow(self, i):
        """
        Get a deep copy of a row in the store for a given index.
        """
        return self.DeepCopyRow(i)

    def GetRows(self):
        """
        Retrieve all of the rows in the store.
        """
        return self.rows

    def GetRowsIterator(self):
        """
        Return an iterator for all of the rows
        """
        for i in xrange(len(self.rows)):
            yield self.DeepCopyRow(i)
