"""
views.py: main views page. Controls business logic of processing forms.

Author: Pete Markowsky <peterm@vodun.org>
"""
from flask import render_template, request
from flask.ext import restful

from app.assembler import Assembler, AssemblerError
from app.assembly_store import AssemblyStore
from app.rest_api import TableRow, TableRowList

from app import app

API = restful.Api(app)
API.add_resource(TableRowList, "/api/table_row", endpoint="tablerowlist_ep")
API.add_resource(TableRow, "/api/table_row/<int:row_index>", endpoint="tablerow_ep")

ASSEMBLY_STORE = AssemblyStore()
ASSEMBLER = Assembler()

@app.route("/bits", methods=["POST"])
def set_bits():
  data = int(request.values['bits'])
  
  if data in (16, 32, 64):
    ASSEMBLY_STORE.bits = data
    ASSEMBLER.Reassemble(ASSEMBLY_STORE)
  return ''

@app.route("/raw_nasm", methods=["POST"])
def raw_nasm():
  data = request.values['lines']
  ASSEMBLER.AssembleRawFile(data, ASSEMBLY_STORE)
  return ''

@app.route("/delete_row", methods=["POST"])
def delete_row():
  index = int(request.values['index'])
  ASSEMBLY_STORE.DeleteRow(index)
  return ''

@app.route("/reset", methods=["POST"])
def reset_assembly_store():
  ASSEMBLY_STORE.Reset()

@app.route("/assemble")
def assemble():
  return ''

@app.route("/")
@app.route("/index")
def index():
  return render_template('main.tpl')