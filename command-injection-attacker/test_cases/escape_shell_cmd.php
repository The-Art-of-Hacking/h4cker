<?php
# filename: escape_shell_cmd.php
# vulnerable to the additional alternative command separator 0x1A only working after being written to a BAT file (http://seclists.org/fulldisclosure/2016/Nov/67)
# sample exploit: '?dir=.%1a[MALICIOUS_COMMAND]'

	$command = 'dir '.$_GET['dir'];
	$escaped_command = escapeshellcmd($command); 
	file_put_contents('out.bat',$escaped_command);
	echo system('out.bat');
?>
<a href="?dir=.">clickme</a>
