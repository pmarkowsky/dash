<!DOCTYPE html>
<html lang="en">
<head>
    <link href="{{url_for('static', filename='css/bootstrap.min.css')}}" rel="stylesheet" media="screen">
    <link href="{{ url_for('static', filename='css/bootstrap.css')}}" rel="stylesheet">
    <link href="{{ url_for('static', filename='css/local.css')}}" rel="stylesheet">
    <link rel="stylesheet" type="text/css" href="{{url_for('static', filename='css/jquery-ui.css')}}">
    <script src="{{ url_for('static', filename='js/jquery-latest.js') }}"></script>
    <script src="{{ url_for('static', filename='js/jquery-ui-1.10.4.min.js') }}"></script>
    <script src="{{url_for('static', filename='js/bootstrap.min.js')}}"></script>
    <script src="{{url_for('static', filename="js/save.js")}}"></script>
    <script src="{{url_for('static', filename="js/filter.js")}}"></script>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body>
  <nav class="navbar navbar-default" role="navigation">
    <div class="container-fluid">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
          <a class="brand logo" href='/' style="font-family: fantasy;font-size:large;"><img src="{{url_for('static', filename='img/logo.png')}}" style=" width: 64px;">DASH</a>
        </div>
        
        <div class="navbar-collapse collapse">
          <ul class="nav navbar-nav navbar-right">
             <li><a id="save-btn" href="#">Save</a></li>
             <li class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="#">ARCH:<span id="arch-disp">x86</span><span class="caret"></span></a>
                    <ul class="dropdown-menu">
                      <li><a href="#" class="asm-arch-option">x86</a></li>
                      <li><a href="#" class="asm-arch-option">ARM</a></li>
                      <li><a href="#" class="asm-arch-option">ARM64</a></li>
                      <li><a href="#" class="asm-arch-option">MIPS</a></li>
                    </ul>
              </li>
              
             <li class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="#">BITS:<span id="bits-disp">32</span><span class="caret"></span></a>
                    <ul class="dropdown-menu">
                      <li><a href="#" class="asm-bits-option">16</a></li>
                      <li><a href="#" class="asm-bits-option">32</a></li>
                      <li><a href="#" class="asm-bits-option">64</a></li>
                    </ul>
              </li>
              <li class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="#">ENDIANESS:<span id="endian-disp">Little</span><span class="caret"></span></a>
                    <ul class="dropdown-menu">
                      <li><a href="#" class="asm-endian-option">Little</a></li>
                      <li><a href="#" class="asm-endian-option">Big</a></li>
                    </ul>
              </li>
          </ul>
        </div><!--/.nav-collapse -->
        </div><!--/.container-fluid -->
</nav> <!-- navbar -->

{% for message in get_flashed_messages() %}
    <div class="alert alert-info alert-dismissable"><div class="panel panel-info">{{ message }}</div></div>
{% endfor %}

<div class="row">
<div class="col-md-offset-1 col-md-10">
<form class="form-inline">
  <div class="form-group">
    <label class="sr-only" for="exampleInputAmount"></label>
    <div class="input-group">
      <div class="input-group-btn"><button id="filter-btn" type="button" class="btn btn-danger"><span class="glyphicon glyphicon-filter"></span>Filter</button></div>
      <input id="filter-bytes" type="text" class="form-control" id="exampleInputAmount" placeholder="Bytes to filter">
      </div>
      </div>
</form>
</div>
</div>

<!-- Modal -->
<div class="modal fade" id="saveModal" tabindex="-1" role="dialog" aria-labelledby="saveModalLabel" aria-hidden="true">
    <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal" aria-hidden="true">&times;</button>
                 <h4 class="modal-title">Shellcode for scripts</h4>
            </div>
            <div class="modal-body"><textarea class="form-control" id="asm-str"></textarea></div>
            <div class="modal-footer">
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
            </div>
        </div>
        <!-- /.modal-content -->
    </div>
    <!-- /.modal-dialog -->
</div>
<!-- /.modal -->

<div class="container" id="main_container"> 
  <div class="row">
    <div class="col-md-12">
    {% block body %}{% endblock %}
    </div>
  </div>
  <div class="row">
  </div><!-- row -->
 <footer>
 </footer>

</div><!-- container -->
<script>
$(document).ready(function () {
   $( "#save-btn" ).bind( "click", save_shellcode);
   $( "#filter-btn").bind( "click", filter_bytes);
});

</script>
</body>
</html>
