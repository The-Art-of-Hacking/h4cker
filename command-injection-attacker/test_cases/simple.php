<?php
# filename: simple.php
# vulnerable, simply

if(isset($_GET['dir'])) echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
?>
<a href="?dir=.">clickme</a>
