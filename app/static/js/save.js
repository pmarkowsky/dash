function save_shellcode() {
  var asm_str = "";
  $.ajax({
      type: 'GET',
      contentType: 'application/json',
      url: "/api/save",
      success: function(data) {asm_str = data;},
      dataType: 'text',
      async:false
    });
  $("#asm-str").val(asm_str);
  $("#saveModal").modal('show');
}