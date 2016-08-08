function filter_bytes() {
  var filter_str = $("#filter-bytes").val();
  var result = "";
  $.ajax({
      type: 'POST',
      contentType: 'application/json',
      url: "/api/filter_bytes",
      success: function(data) {},
      data: JSON.stringify({"filter_bytes": filter_str.toUpperCase()}),
      dataType: 'json',
      async:false
    });
    update_asm_rows(); 
}