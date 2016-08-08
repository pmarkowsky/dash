{% extends "layout.tpl" %}
{% block body %}
<div id="asm-table">
<table id="main-asm-table" class="table table-condensed table-hover">
 <thead>
 <th></th><th>Offset</th><th>Address</th><th>Label</th><th>Opcodes</th><th>Mnemonics</th><th>Comments</th>
 </thead>
 <tbody>
 </tbody>
 </table>
</div>

<script>
var current_row = 0;
var current_table_rows = []

var submit_data_to_url = function (url, field) {
  return function (event) {
      event.stopPropagation();
      var asm_row_id = $(this).attr("row-id");
      var row_url = url + asm_row_id;
      var text = $(this).val();
      
      if (event.which  == 13) { //13 is the enter key
        $(this).off();
        var data = {}
        data[field] = text;
        
        $.ajax({contentType: 'application/json',
                type: "PUT",
                data: JSON.stringify(data),
                dataType: 'json',
                url: row_url});
        update_asm_rows();
      }
    }
}

var submit_addr = submit_data_to_url("/api/table_row/", "address");
var submit_label = submit_data_to_url("/api/table_row/", "label");
var submit_opcode = submit_data_to_url("/api/table_row/", "opcode");
var submit_mnemonic = submit_data_to_url("/api/table_row/", "mnemonic");
var submit_comment = submit_data_to_url("/api/table_row/", "comment");


// this is used to autocomplete labels for jmp and call instructions
var mnemonic_auto_complete = function (elem) {

  $(elem).autocomplete({
    source: function (request, response) {
        var matcher = new RegExp("^(call\\s|j\\w\\s|jn\\w\\s|jmp\\s)$", "i");
        var label_autocomplete_list =  [];
        
        // if the  current text starts with a jmp, j*, or call
        if (matcher.test(request.term)) {
            var label_autocomplete_list =  [];
            
            $(".asm-label").each(function () { 
                  if ($(this).text() !== "") {
                        label_autocomplete_list.push(request.term.toUpperCase() + $(this).text())
                      }
                  });
        }
        response(label_autocomplete_list);
    },
  });
}

var submit_function_cb = function (submit_func) {
  return function () {
      var cur_content = $(this).text()
      var el = $('<input style="width:100%"></input>');
      var row_id = $(this).parent("tr").attr("id");
      el.attr("row-id", row_id);
      $(this).off();
      el.on("keydown", submit_func);
      el.val(cur_content);
      $(this).html(el);
      el.focus();
  }
}

var submit_function_cb_with_auto_complete = function (submit_func) {
  return function () {
      var cur_content = $(this).text()
      var el = $('<input style="width:100%"></input>');
      var row_id = $(this).parent("tr").attr("id");
      el.attr("row-id", row_id);
      $(this).off();
      el.on("keydown", submit_func);
      el.val(cur_content);
      $(this).html(el);
      el.focus();
      mnemonic_auto_complete(el);
  }
}

// covert row data to json
function update_current_row_id(event) {
  event.stopPropagation();
  current_row = +$(this).attr("id");
}

  
var addr_func  = submit_function_cb(submit_addr);
var comment_func = submit_function_cb(submit_comment); 
var label_func = submit_function_cb(submit_label);
var opcode_func = submit_function_cb(submit_opcode);
var mnem_func = submit_function_cb_with_auto_complete(submit_mnemonic);

var hotkeys_func = function (event) {
   switch(event.which) {
   case 68:  // if 'd' is pressed delete current row
     var row_url = "/api/table_row/" + current_row;
     $.ajax({contentType: 'application/json',
             type: "DELETE",
             url: row_url});
     break;
     
   // if i is pressed and we're not editing insert a row
   default: //do nothing
     break;
   }
   update_asm_rows();
}

function set_bits(event) {
  event.stopImmediatePropagation();
  var old_bits = $("#bits-disp").text();
  var new_bits = $(this).text();
  $("#bits-disp").text($(this).text());
  //get the currently selected architechture
  var arch = $("#arch-disp").text();
  //get the currently selected endianess
  var endianess = $("#endian-disp").text();
  if (!set_archmode(arch, bits, endianess)) {
   $("#bits-disp").text(old_bits);
  }
}

function set_arch(event) {
  event.stopImmediatePropagation();
  var old_arch = $("#arch-disp").text();
  var arch = $(this).text();
  $("#arch-disp").text($(this).text());
  var bits = $("#bits-disp").text();
  var endianess = $("#endian-disp").text();
  if (!set_archmode(arch, bits, endianess)) {
    $("#arch-disp").text(old_arch);
  }
}

function set_endianess(event) {
  event.stopImmediatePropagation();
  var old_endianess = $("#endian-disp").text();
  var endianess = $(this).text();
  $("#endian-disp").text($(this).text());
  var arch = $("#arch-disp").text();
  var bits = $("#bits-disp").text();
  if(!set_archmode(arch, bits, endianess)) {
    $("#endian-disp").text(old_endianess);
  }
}

function set_archmode(arch, bits, endianess) {
  var arch_mode_str = arch + "-" + bits;
  var arch_modes = {"x86-16": 0,
                    "x86-32": 1,
                    "x86-64": 2,
                    "ARM-16": 3,
                    "ARM-32": 4,
                    "ARM64-64": 5,
                    "MIPS-32": 6}
  var arch_mode = arch_modes[arch_mode_str]
  var endianess_vals = {"Little": "0", "Big": 1}
  endianess = endianess_vals[endianess];
  if (arch_mode !== undefined && endianess !== undefined) {
    var ret_val = false;
    $.ajax({
      type: 'POST',
      contentType: 'application/json',
      url: "/api/settings",
      data: JSON.stringify({"archmode": arch_mode, "endian": endianess}),
      success: function() {ret_val = true;},
      dataType: 'json',
      async:false
    });
    update_asm_rows();
    return ret_val;
  } else {
    return false;
  }
}

function build_asm_table_rows(table_rows) {
  var table_body = $("#main-asm-table > tbody");
  table_body.html("");
  
  for (var i = 0; i < table_rows.length; i++) {
    var row = table_rows[i];
    var html_row = $("<tr></tr>");
    html_row.attr({id: i});
    html_row.addClass("asm-row");
    
    if (row.error !== 0) {
      html_row.addClass("danger");
    }
    html_row.append('<td><input class="asm-row-check" id="rowid-' + row.index + 
                    '" type="checkbox"></input></td>');
    html_row.append('<td class="asm-offset">' + row.offset + '</td>');
    html_row.append('<td class="asm-addr">' + row.address + '</td>');
    html_row.append('<td class="asm-label">' + row.label + '</td>');
    html_row.append('<td class="asm-opcode">' + row.opcode + '</td>');
    html_row.append('<td class="asm-mnemonic">' + row.mnemonic + '</td>');
    html_row.append('<td class="asm-comment">' + row.comment + '</td>');
    table_body.append(html_row);
  }
  table_body.show();
}

//javascript function to get the new state of asm rows
function update_asm_rows() {
  $.getJSON("/api/table_row", function(data) {
     current_table_rows = data.rows;
     build_asm_table_rows(current_table_rows);
     $(".asm-addr").off();
     $(".asm-addr").on("click", addr_func);
     $(".asm-comment").off();
     $(".asm-comment").on("click", comment_func); 
     $(".asm-opcode").off();
     $(".asm-opcode").on("click", opcode_func);
     $(".asm-mnemonic").off();
     $(".asm-mnemonic").on("click", mnem_func);
     $(".asm-label").off();
     $(".asm-label").on("click", label_func);
     $(".asm-arch-option").on("click", set_arch);
     $(".asm-bits-option").on("click", set_bits);
     $(".asm-endian-option").on("click", set_endianess);
     $(".asm-row").hover(update_current_row_id);
  });
  
  $.getJSON("/api/filter_bytes", function (data) {
    $("#filter-bytes").val(data.filter_bytes);
  });
}

$(document).ready(function () {
    update_asm_rows();
});
</script>
{% endblock %}