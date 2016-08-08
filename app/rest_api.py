"""
rest_api.py: a REST API for updating and retrieving assembly information in the asm_store.
"""
import binascii

#third-party modules
from flask import jsonify, abort, render_template
from flask.ext.restful import Resource, reqparse, marshal_with, fields

#app specific modules
from assembler import Assembler
from assembler import X86_16,X86_32,X86_64, ARM_16,ARM_32,ARM_64,MIPS_32, \
     BIG_ENDIAN,LITTLE_ENDIAN

from assembly_store import AssemblyStore, AssemblyStoreError, RowData

ASSEMBLY_STORE = AssemblyStore()
ASSEMBLER = Assembler()

TABLE_ROW_FIELDS = {"index": fields.Integer,
                    "offset": fields.Integer,
                    "address": fields.String,
                    "label": fields.String,
                    "error": fields.Integer,
                    "opcode": fields.String,
                    "mnemonic": fields.String,
                    "comment": fields.String,
                    "in_use": fields.Boolean,
                    "targets": fields.List(fields.Integer),
                    "is_call_or_branch": fields.Boolean,
                    "is_a_data_defintion_inst": fields.Boolean}

TABLE_ROW_LIST_FIELDS = {"rows": fields.List(fields.Nested(TABLE_ROW_FIELDS))}


class TableRowList(Resource):
    """
    Simple API to retrieve all rows as JSON.
    """
    @marshal_with(TABLE_ROW_LIST_FIELDS)
    def get(self):
        """
        Get all of the rows in the store.
        """
        row_data = [row.ToDict() for row in ASSEMBLY_STORE.GetRows()]
        return {"rows": row_data}


class TableRow(Resource):
    """
    Rest API responsible for updating and retrieving individual table rows.
    """
    def InsertMultipleRowsByMnemonic(self, current_row, mnemonics):
        """
        Insert multiple instructions at once using the mnemonic field.
        """
        #update current row
        mnemonic_fields = mnemonics[0].split() 
        operation_str = mnemonic_fields[0].upper()
        current_row.SetMnemonic(operation_str + ' ' + ' '.join(mnemonic_fields[1:]))
        ASSEMBLY_STORE.UpdateRow(current_row.index, current_row)

        for i in xrange(1, len(mnemonics)):
            mnemonic_fields = mnemonics[i].split() 
            operation_str = mnemonic_fields[0].upper()
            mnemonic_str = operation_str + ' ' + ' '.join(mnemonic_fields[1:])
            row = RowData(0, "", 0, "", mnemonic_str, "", 
                          index=current_row.index + i, in_use=True)
            ASSEMBLY_STORE.InsertRowAt(i, row)

    @marshal_with(TABLE_ROW_FIELDS)
    def put(self, row_index):
        """
        Edit the values of a row via an HTTP PUT request.

        Args:
          row_index: an integer index into the assembly store

        Returns:
          A tuple of http return code and a dictionary to be serialized to JSON
        """
        try:
            row = ASSEMBLY_STORE.GetRow(row_index)
        except AssemblyStoreError:
            abort(404)

        parser = reqparse.RequestParser()
        parser.add_argument('offset', type=int, default=row.offset, 
                            location='json')
        parser.add_argument('label', default=row.label, location='json')
        parser.add_argument('address', type=str, default=row.address,
                            location='json')
        parser.add_argument('opcode', default=row.opcode, location='json')
        parser.add_argument('mnemonic', default=row.mnemonic, location='json')
        parser.add_argument('comment', default=row.comment, location='json')
        #this defaults to true as adding any data makes a row in use
        parser.add_argument('in_use', default=True, location='json')
        args = parser.parse_args()
        row.offset = args.offset
        row.SetLabel(args.label)
        row.SetAddress(args.address)
        row.SetComment(args.comment)
        row.in_use = args.in_use

        ASSEMBLY_STORE.UpdateRow(row.index, row)

        if str(args.opcode).strip() != row.opcode:
            row.SetOpcode(args.opcode)
            ASSEMBLY_STORE.UpdateRow(row.index, row)

            if row.error:
                return row.ToDict()

            ASSEMBLER.Disassemble(row.index, ASSEMBLY_STORE)
        else:

            if args.mnemonic != row.mnemonic:
                new_mnemonics = args.mnemonic.split(';')
                self.InsertMultipleRowsByMnemonic(row, new_mnemonics)
            else:
                ASSEMBLY_STORE.UpdateRow(row.index, row)
            ASSEMBLER.Assemble(ASSEMBLY_STORE)

        row = ASSEMBLY_STORE.GetRow(row.index)
        return row.ToDict()


    @marshal_with(TABLE_ROW_FIELDS)
    def get(self, row_index):
        try:
            row = ASSEMBLY_STORE.GetRow(row_index)
        except AssemblyStoreError:
            abort(404)

        return row.ToDict()


class AssemblyStoreSettings(Resource):
    """
    REST calls for changing assembler arch settings.
    """
    def valid_archmode(self, value):
        """
        Ensure that the arch and mode value are within the supported range
        """
        result = int(value)
        if result not in (X86_16, X86_32, X86_64, ARM_16, ARM_32, ARM_64, MIPS_32):
            raise ValueError("Invalid arch_mode specified")
        else:
            return result

    def valid_endianess(self, value):
        """
        Ensure that the endian
        """
        result = int(value)
        if result not in (BIG_ENDIAN, LITTLE_ENDIAN):
            raise ValueError("Invalid endianess specified")
        else:
            return result

    def post(self):
        """
        Handle setting the architechture settings.
        """
        parser = reqparse.RequestParser()
        parser.add_argument('archmode', type=self.valid_archmode, required=True,
                            location='json')
        parser.add_argument('endian', type=self.valid_endianess, required=True,
                            location='json')
        args = parser.parse_args()
        ASSEMBLER.SetArchAndMode(args.archmode, args.endian)
        ASSEMBLY_STORE.ClearErrors()
        ASSEMBLER.DisassembleAll(ASSEMBLY_STORE) 
        return jsonify(success="1")

    def get(self):
        """
        Return the assembler's current arch, mode and endianess
        """
        arch_mode = ASSEMBLER.arch_mode
        endianess = ASSEMBLER.endianess
        return jsonify(arch_mode=arch_mode, endianess=endianess)
    
class AssemblyStoreFilterBytes(Resource):
    """
    REST calls for changing assembler arch settings.
    """
    def post(self):
        """
        Handle setting the architechture settings.
        """
        parser = reqparse.RequestParser()
        parser.add_argument('filter_bytes', type=str, required=True,
                            location='json')
        
        args = parser.parse_args()
        ASSEMBLY_STORE.filter_bytes = binascii.unhexlify(args.filter_bytes)
        
        ASSEMBLY_STORE.ClearErrors()
        
        for row in ASSEMBLY_STORE.GetRowsIterator():
            ASSEMBLER.CheckOpcodeBytes(row, ASSEMBLY_STORE)
            
        return jsonify(success="1")


class SaveModal(Resource):
    """
    Save shellcode handler (this produces the modal html)
    """
    def GetShellcodeString(self):
        """
        Create a string that can be imported in python / ruby
        """
        sc_text = "shellcode = ("
        for row in ASSEMBLY_STORE.GetRowsIterator():
            if row.in_use:
                sc_text += "%s # %s" % (repr(row.opcode).replace("\\\\", "\\"), 
                                        row.mnemonic)
                if row.comment:
                    sc_text += "--  %s" % row.comment
                sc_text += "\n"
        sc_text += ")"
        
        return sc_text

    def get(self):
        return self.GetShellcodeString()
    
    