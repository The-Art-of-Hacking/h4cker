<?php
# filename: arg_escape_shell_cmd.php
# should be vulnerable to argument injection
# although it is not possible to use any exec variants (; is escaped)
# we can still, for example:

# 1) create files with arbitrary names:
# GET /test_cases/GET/arginj_escape_shell_cmd.php?dir=arginj_escape_shell_cmd.php%20-fprint%20owned.php HTTP/1.1
# and then figure out how to inject code into it:
# 

	$command = 'find -iname ';
	$escaped_arg = escapeshellcmd($_GET['dir']); // while escapeshellarg should be used instead


	$all=$command.$escaped_arg;
	echo "Executing $all:<br />";
	echo system($all);


?>
<a href="?dir=.">clickme</a>
