<?php
# tar argument injection via --checkpoint-action=ACTIOLqN
# evil payload:
# /test_cases/GET/tar.php?dir=/dev/null%20/dev/null%20--checkpoint=1%20--checkpoint-action=exec=%27touch%20/tmp/ownedd%27
# HINT: for some reason does not work (tar is executed and does not even return an error, the same command works just fine when typed from an actual terminal
# so tar might be silently dropping the attempt to execute the command as current process (e.g. Apache) has no terminal attached

function cmd_exec($cmd, &$stdout, &$stderr)
{
    $outfile = tempnam(".", "cmd");
    $errfile = tempnam(".", "cmd");
    $descriptorspec = array(
        0 => array("pipe", "r"),
        1 => array("file", $outfile, "w"),
        2 => array("file", $errfile, "w")
    );
    $proc = proc_open($cmd, $descriptorspec, $pipes);
    
    if (!is_resource($proc)) return 255;

    fclose($pipes[0]);    //Don't really want to give any input

    $exit = proc_close($proc);
    $stdout = file($outfile);
    $stderr = file($errfile);

    unlink($outfile);
    unlink($errfile);
    return $exit;
}

	## user provides both names (and arguments if they want :D)

	$command = 'tar -cf ';
	$escaped_arg = escapeshellcmd($_GET['dir']); // while escapeshellarg should be used instead	
	
	$all = $command.$escaped_arg;
	echo "Command after concatenation: $all\n";
	$output='';
	$error='';
	cmd_exec($all,$output,$error);

	echo "Output:\n";
	foreach($output as $out)
	{
		echo "$out<br />";
	}

	echo "Error:\n";
	foreach($error as $err)
	{
		echo "$err<br />";
	}

?>
<a href="?dir=curr.tar">clickme</a>

