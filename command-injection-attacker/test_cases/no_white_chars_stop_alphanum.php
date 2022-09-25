<?php
# filename: no_white_chars_stop_alphanum.php
# vulnerable, the payload needs to end with an alphanum character
#

echo "Dir contents are:\n";
if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir'])&&preg_match('/\w+$/',$_GET['dir']))
{
	 echo "<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=a">clickme</a>
