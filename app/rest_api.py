"""
rest_api.py: a REST API for updating and retrieving assembly information in the asm_store.
"""
import binascii

#third-party modules
from flask import jsonify, abort, request
from flask.ext.restful import Resource, reqparse, marshal, marshal_with, fields

#app specific modules
from assembler import Assembler, AssemblerError
from assembly_store import AssemblyStore, AssemblyStoreError, RowData

ASSEMBLY_STORE = AssemblyStore()
ASSEMBLER = Assembler()

TABLE_ROW_FIELDS = {"index": fields.Integer,
                    "offset": fields.Integer,
                    "address": fields.String,
                    "label": fields.String,
                    "opcode": fields.String,
                    "mnemonic": fields.String,
                    "comment": fields.String,
                    "in_use": fields.Boolean,
                    "targets": fields.List(fields.Integer),
                    "is_call_or_branch": fields.Boolean,
                    "is_a_data_defintion_inst": fields.Boolean}

TABLE_ROW_LIST_FIELDS = {"rows": fields.List(fields.Nested(TABLE_ROW_FIELDS))}


class TableRowList(Resource):
    def post(self):
        """
        Add a new table row at an index
        """
        parser = reqparse.RequestParser()
        parser.add_argument('index', type=int, required=True, location='json')
        
        args = parser.parse_args()
        row = RowData(0, '', 0, '' ,'', '', index)
        AssemblyStore.InsertRowAt(index, row)
        
        return marshal(row.ToDict(), TABLE_ROW_FIELDS), 201
        
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
    def insert_multiple_rows_by_mnemonic(self, current_row, mnemonics):
        """
        Insert mutliple instructions at once using the mnemonic field.
        """
        #update current row
        current_row.SetMnemonic(mnemonics[0])
        ASSEMBLY_STORE.UpdateRow(current_row.index, current_row)
        
        for i in xrange(1, len(mnemonics)):
            row = RowData(0, "", 0, "", mnemonics[i], "", 
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
                self.insert_multiple_rows_by_mnemonic(row, new_mnemonics)
                
            ASSEMBLY_STORE.UpdateRow(row.index, row)
            ASSEMBLER.Assemble(row.index, ASSEMBLY_STORE)
            
        row = ASSEMBLY_STORE.GetRow(row.index)
        return row.ToDict()
                
        
    @marshal_with(TABLE_ROW_FIELDS)
    def get(self, row_index):
        try:
            row = ASSEMBLY_STORE.GetRow(row_index)
        except AssemblyStoreError:
            abort(404)
            
        return row.ToDict()
    
    
class AssemblyStoreModeSettings(Resource):
    """
    REST calls for changing assembler bit settings.
    """
    def valid_bits(self, value):
        """
        Ensure that the bits values are within our supported range of [16, 32, 64]
        """

        result = int(value)
        if result not in (16, 32, 64):
            raise ValueError("Invalid bits")
        else:
            return result
        
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('bits', type=self.valid_bits, required=True,
                            location='json')
        args = parser.parse_args()
        ASSEMBLY_STORE.bits = args.bits
        ASSEMBLER.Reassemble(ASSEMBLY_STORE) 
        return jsonify(success=True, bits=args.bits), 201
    
    def get(self):
        return jsonify(bits=ASSEMBLY_STORE.bits)
    
    
class AssemblyStoreArchSettings(Resource):
    """
    REST calls for changing assembler arch settings.
    """
    def valid_bits(self, value):
        """
        Ensure that the bits values are within our supported range of [16, 32, 64]
        """
        result = int(value)
        if result not in (16, 32, 64):
            raise ValueError("Invalid bits")
        else:
            return result
        
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('bits', type=self.valid_bits, required=True,
                            location='json')
        args = parser.parse_args()
        ASSEMBLY_STORE.bits = args.bits
        ASSEMBLER.Reassemble(ASSEMBLY_STORE) 
        return jsonify(success=True, bits=args.bits), 201
    
    def get(self):
        return jsonify(bits=ASSEMBLY_STORE.bits)