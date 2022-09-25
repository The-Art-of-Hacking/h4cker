<?php
# filename: no_white_chars_start_digit.php
# vulnerable to payloads starting with a digit

if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir'])&&preg_match('/^\d+/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=1">clickme</a>
