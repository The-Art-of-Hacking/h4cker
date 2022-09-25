<?php
# filename: arginj1.php
# vulnerable to argument injection
#

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
 

# wget has nice, injection-friendly syntax (many might not be aware of while writing code that calls it):
#   Option Syntax
#       Since Wget uses GNU getopt to process command-line arguments, every option has a long form along with the short one.  Long
#       options are more convenient to remember, but take time to type.  You may freely mix different option styles, or specify
#       options after the command-line arguments.  Thus you may write:

#               wget -r --tries=10 http://fly.srk.fer.hr/ -o log

	$command = 'wget';
	$escaped_arg = escapeshellarg($_GET['url']); // while escapeshellarg should be used instead	
	$all=$command.' "'.$escaped_arg.'"';

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
<a href="?url=">clickme</a>
