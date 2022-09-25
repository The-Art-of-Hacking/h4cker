<?php
# filename: no_white_chars.php 
# vulnerable, just use a creative non-white alternative argument separator
# 

if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=.">clickme</a>
