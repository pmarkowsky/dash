"""
views.py: main views page. Controls business logic of processing forms.

Author: Pete Markowsky <peterm@vodun.org>
"""
from flask import render_template
from flask.ext import restful

from app.rest_api import AssemblyStoreSettings, TableRow, TableRowList
from app import app

API = restful.Api(app)
API.add_resource(AssemblyStoreSettings, "/api/settings", 
                 endpoint="settings_ep")
API.add_resource(TableRow, "/api/table_row/<int:row_index>", 
                 endpoint="tablerow_ep")
API.add_resource(TableRowList, "/api/table_row", 
                 endpoint="tablerowlist_ep")

@app.route("/")
@app.route("/index")
def index():
  return render_template('main.tpl')