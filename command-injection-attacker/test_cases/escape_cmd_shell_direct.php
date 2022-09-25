<?php
# filename: escape_cmd_shell_direct.php
# does not look vulnerable, but we need to make sure :D
	$command = 'dir '.$_GET['dir'];
	$escaped_command = escapeshellcmd($command); 
	system($escaped_command); 
?>
<a href="?dir=.">clickme</a>
