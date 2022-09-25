<?php
# filename: no_white_chars_windows_blind.php
# vulnerable, no response directly shown
# 

if(isset($_GET['dir'])&&!preg_match('/\s+/',$_GET['dir']))
{		 
	shell_exec("dir {$_GET['dir']}>../listing.txt");
	echo "The index file has been updated.";
}
else
{
	echo "GET[dir] not set.";
}
?>


<a href="?dir=.">clickme</a>
