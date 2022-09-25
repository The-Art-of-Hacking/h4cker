<?php
if(isset($_POST['dir'])&&!preg_match('/\s+/',$_POST['dir'])&&preg_match('/^\w+/',$_POST['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_POST['dir']}");
}
?>
