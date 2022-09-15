# *************************************************************************************** #
# ---------------------------------- EULA NOTICE ---------------------------------------- #
#                     Agreement between "Haroon Awan" and "You"(user).                    #
# ---------------------------------- EULA NOTICE ---------------------------------------- #
#  1. By using this piece of software your bound to these point.                          #
#  2. This an End User License Agreement (EULA) is a legal between a software application #
#     author "Haroon Awan" and (YOU) user of this software.                               #
#  3. This software application grants users rights to use for any purpose or modify and  #
#     redistribute creative works.                                                        #
#  4. This software comes in "is-as" warranty, author "Haroon Awan" take no responsbility #
#     what you do with by/this software as your free to use this software.                #
#  5. Any other purpose(s) that it suites as long as it is not related to any kind of     #
#     crime or using it in un-authorized environment.                                     #
#  6. You can use this software to protect and secure your data information in any        #
#     environment.                                                                        #
#  7. It can also be used in state of being protection against the unauthorized use of    #
#     information.                                                                        #
#  8. It can be used to take measures achieve protection.                                 #
# *************************************************************************************** #

#!/bin/bash

red="\e[0;31m"
green="\e[0;32m"
off="\e[0m"

function banner() {
clear
echo "                                                                                               ";
echo "                                                                                               ";
echo "	         ..#######....######...#######..#######..######....###....##....######..      "; 
echo "		 .##.....##..##....##....##.....##...##..##...##...##.....##...##......	 "; 
echo "        	 .##.....##..##..........##.....##...##..##....##..##.....##...##.	 "; 
echo "        	 .##.....##..##..........##.....##...##..######....##.....##....######.	 "; 
echo "        	 .##.....##..##..........##.....##...##..##........##.....##........##.	 "; 
echo "        	 .##.....##..##....##....##.....##...##..##........##.....##........##.	 "; 
echo "        	 ..#######....######.....##.....#######..##........#########...######...	 ";  
echo "                                                                                               ";
echo "         	        An Automated Database Hacking Software     Version 1.9a        ";   
echo "         	                        [Coded By: Haroon Awan]                                       ";
echo "         	                    [Contact: mrharoonawan@gmail.com]                                  ";
echo "                                                                                               ";
echo "                                                                                               ";
echo "                                                                                               ";
}

function linux() {
echo -e "$red [$green+$red]$off Installing Perl ...";
sudo apt-get install -y perl
echo -e "$red [$green+$red]$off Installing JSON Module ...";
cpan install JSON
echo -e "$red [$green+$red]$off Installing Extra Perl Modules ...";
echo "y" | cpan install WWW::Mechanize
echo "y" | cpan install use HTML::TokeParser
echo "y" | cpan install Term::ANSIColor
echo "y" | cpan install Mojo::DOM
echo "y" | cpan install Data::Dumper
echo "y" | cpan install Win32::Console::ANSI
echo "y" | cpan install HTML::TableExtract
echo "y" | cpan install Data::Validate::Domain
echo "y" | cpan install LWP::Protocol::https
echo "y" | cpan install Mozilla::CA
echo "y" | cpan install Bundle::LWP


echo -e "$red [$green+$red]$off Checking directories..."
if [ -d "/usr/share/octopus" ]; then
    echo -e "$red [$green+$red]$off A Directory octopus Was Found! Do You Want To Replace It? [Y/n]:" ;
    read replace
    if [ "$replace" = "Y" ]; then
      sudo rm -r "/usr/share/octopus"
      sudo rm "/usr/share/icons/octopus.png"
      sudo rm "/usr/share/applications/octopus.desktop"
      sudo rm "/usr/local/bin/octopus"

else
echo -e "$red [$green+$red]$off If You Want To Install You Must Remove Previous Installations";
        exit
    fi
fi 

echo -e "$red [$green+$red]$off Installing ...";
echo -e "$red [$green+$red]$off Creating Symbolic Link ...";
echo -e "#!/bin/bash
perl /usr/share/octopus/octopus.pl" '${1+"$@"}' > "octopus";
    chmod +x "octopus";
    sudo mkdir "/usr/share/octopus"
    sudo cp "installer.sh" "/usr/share/octopus"
    sudo cp "octopus.pl" "/usr/share/octopus"
    sudo cp "config/octopus.jpeg" "/usr/share/icons"
    sudo cp "config/octopus.desktop" "/usr/share/applications"
    sudo cp "octopus" "/usr/local/bin/"
    rm "octopus";

echo -e "$red [$green+$red]$off Installing dependencies..."
echo "y" | apt-get install xdg-utils
echo "y" | apt-get install cargo
echo "y" | apt-get install python-yaml
echo "y" | apt-get install hping3
echo "y" | apt-get install python2.7
echo "y" | apt-get install python3
echo "y" | apt-get install x11-utils xutils-dev imagemagick libxext-dev xspy
echo "y" | apt-get install golang
echo "y" | apt-get install curl
echo "y" | apt-get install nfs-common
echo "y" | apt-get install smbclient
echo "y" | apt-get install gem
perl -MCPAN -e shell
install LWP::Protocol::https
quit
echo "y" | git clone https://github.com/the-robot/sqliv.git
cd sqliv
chmod u+x *
cp * ../
cd ..
sudo python2 setup.py -i
echo "y" | git clone https://github.com/JukArkadiy/odat.git
cd odat
chmod u+x *
cp * ../
cd ..
echo "y" | apt-get install nmap
echo "y" | apt-get install xrdp
pip install jsbeautifier
pip install tabulate
pip install terminaltables
pip install argparse
pip install requests
pip install bs4
pip install termcolor
pip install terminaltables
pip install nyawc
pip install request
chmod u+x *.sh
cp * -r /usr/share/octopus
cp *.sh /usr/share/octopus
cat traceroute-function >> ~/.bashrc
source ~/.bashrc

if [ -d "/usr/share/octopus" ] ;
then
echo -e "$red [$green+$red]$off octopus Successfully Installed, Starting";
sleep 2;
octopus
else
echo -e "$red [$green+$red]$off octopus Cannot Be Installed. Trying using Portable Edition !";
    exit
fi 
}

if [ -d "/usr/bin/" ];then
banner
echo -e "$red [$green+$red]$off octopus Will Be Installed In Your System";
linux
else
echo -e "$red [$green+$red]$off octopus Cannot Be Installed. Trying using Portable Edition !";
    exit
fi
