<?php
# filename: simple_no_space.php
# vulnerable, an argument separator other than whitespace needs to be used (e.g. tab, but also $IFS$9 or %25ProgramFiles:~10,1%25)
# 

if(isset($_GET['dir'])&&!preg_match('/ /',$_GET['dir'])) echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
?>
<a href="?dir=.">clickme</a>
