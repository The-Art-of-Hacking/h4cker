<?php
# filename: no_white_chars_no_colon_no_pipe_no_ampersand_no_dollar.php
# does not appear to be vulnerable to newline injection (the \s+ switch)
# while detection of the backtick injection is very hard; this works:
# ?dir=`id`
# but there is no way to separate arguments, while {nslookup,DOMAIN} does not work, at least not with dash (as far as I remember I tested this before and it olny worked with bash)
# so, with dash on the other side this is currently not being detected

if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir'])&&!preg_match('/&|\||;|\$/',$_GET['dir']))
{
	 echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
}
?>
<a href="?dir=.">clickme</a>
