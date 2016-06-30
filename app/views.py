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

@app.route("/")
@app.route("/index")
def index():
  return render_template('main.tpl')