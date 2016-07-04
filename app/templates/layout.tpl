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
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body>
<nav class="navbar navbar-default navbar-grey blue" role="navigation">
        <div class="navbar-header">
          <button type="button" class="navbar-toggle" data-toggle="collapse" data-target=".navbar-collapse">
            <span class="sr-only">Toggle navigation</span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
            <span class="icon-bar"></span>
          </button>
        </div>
        
        <div class="navbar-inner">
          <a class="brand logo" href='/'>DASH</a>
        </div>
        
        <div class="navbar-collapse collapse">
          <ul class="nav navbar-nav pull-right">
             <li><button class="btn">
                <div class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="#">ARCH:<span id="arch-disp">x86</span><span class="caret"></span></a>
                    <ul class="dropdown-menu scrollable-menu" role="menu" aria-labelledby="dropdownMenu1">
                      <li class="asm-arch-option" role="presentation" id="set-arch-x86">x86</li>
                      <li class="asm-arch-option" role="presentation" id="set-bits-arm">ARM</li>
                      <li class="asm-arch-option" role="presentation" id="set-bits-arm64">ARM64</li>
                      <li class="asm-arch-option" role="presentation" id="set-bits-mips">MIPS</li>
                    </ul>
                </div>
              </button></li>

             <li><button class="btn">
                <div class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="#">BITS:<span id="bits-disp">32</span><span class="caret"></span></a>
                    <ul class="dropdown-menu scrollable-menu" role="menu" aria-labelledby="dropdownMenu1">
                      <li class="asm-bits-option" role="presentation" id="set-bits-16">16</li>
                      <li class="asm-bits-option" role="presentation" id="set-bits-32">32</li>
                      <li class="asm-bits-option" role="presentation" id="set-bits-64">64</li>
                    </ul>
                </div>
              </button></li>
              <li><button class="btn">
                <div class="dropdown">
                    <a class="dropdown-toggle" data-toggle="dropdown" href="#">ENDIANESS:<span id="endian-disp">Little</span><span class="caret"></span></a>
                    <ul class="dropdown-menu scrollable-menu" role="menu" aria-labelledby="dropdownMenu1">
                      <li class="asm-endian-option" role="presentation" id="set-little-endian">Little</li>
                      <li class="asm-endian-option" role="presentation" id="set-big-endian">Big</li>
                    </ul>
                </div>
              </button></li>

          </ul>
        </div><!--/.nav-collapse -->
</nav> <!-- navbar -->

{% for message in get_flashed_messages() %}
    <div class="alert alert-info alert-dismissable"><div class="panel panel-info">{{ message }}</div></div>
{% endfor %}


<div class="container" id="main_container"> 
  <div class="row">
    <div class="col-md-12">
    {% block body %}{% endblock %}
    </div>
  </div>
  <div class="row">
  </div><!-- row -->
 <footer>
        <p>&copy; Dash 2016</p>
 </footer>

</div><!-- container -->
</body>
</html>
