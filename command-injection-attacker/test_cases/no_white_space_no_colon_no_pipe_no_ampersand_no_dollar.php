<?php
# filename: no_white_spaces_no_colon_no_pipe_no_ampersand_no_dollar.php
# vulnerable to newline
# 
if(isset($_GET['dir'])&&!preg_match('/ /',$_GET['dir'])&&!preg_match('/&|\||;|\$/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=.">clickme</a>
