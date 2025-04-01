#!/usr/bin/env bash
# WebSploit installation script
# Author: Omar Ωr Santos
# Web: https://websploit.org
# Twitter: @santosomar
# Version: 4.0


clear
echo "

██╗    ██╗███████╗██████╗ ███████╗██████╗ ██╗      ██████╗ ██╗████████╗
██║    ██║██╔════╝██╔══██╗██╔════╝██╔══██╗██║     ██╔═══██╗██║╚══██╔══╝
██║ █╗ ██║█████╗  ██████╔╝███████╗██████╔╝██║     ██║   ██║██║   ██║
██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔═══╝ ██║     ██║   ██║██║   ██║
╚███╔███╔╝███████╗██████╔╝███████║██║     ███████╗╚██████╔╝██║   ██║
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚═╝     ╚══════╝ ╚═════╝ ╚═╝   ╚═╝
L A B S      B Y     O M A R   S A N T O S 

https://websploit.org
Author: Omar Ωr Santos
Twitter: @santosomar
Version: 4.0

A collection of tools, tutorials, resources, and intentionally vulnerable 
applications running in Docker containers. WebSploit Labs include 
over 500 exercises to learn and practice ethical hacking (penetration testing) skills.
--------------------------------------------------------------------------------------
"


read -n 1 -s -r -p "Press any key to continue the setup..."

set -e  # Exit immediately if a command exits with a non-zero status
set -u  # Treat unset variables as an error

#--------------------------------------------------
# 1) Check if running as root
#--------------------------------------------------
if [[ $EUID -ne 0 ]]; then
  echo "You need admin privileges in order to install these packages. Please run this script as root (e.g. sudo ./install.sh). Additional details at https://websploit.org"
  exit 1
fi

#--------------------------------------------------
# 2) Basic apt update & install
#--------------------------------------------------
echo "[+] Updating apt and installing base packages..."
apt update -y
apt install -y wget curl git ack-grep vim exuberant-ctags python3-pip python3-venv \
               hostapd ffuf tor jupyter-notebook zaproxy

#--------------------------------------------------
# 3) Install Python-based tools via apt (where possible)
#    This avoids PEP 668 issues for commonly packaged tools
#--------------------------------------------------
echo "[+] Installing Python-based tools via apt where available..."
apt install -y python3-flake8 python3-flask

#--------------------------------------------------
# 4) For Python packages not in apt, use a virtual environment
#    This prevents "externally-managed-environment" errors.
#--------------------------------------------------
echo "[+] Creating a virtual environment for pip-only packages..."
VENV_DIR="/opt/python-tools"
mkdir -p "$VENV_DIR"
python3 -m venv "$VENV_DIR"
# Activate venv
source "$VENV_DIR/bin/activate"

echo "[+] Installing PIP-only packages in the virtual environment..."
# Example packages not in apt:
pip install --upgrade pip
pip install certspy

# Deactivate the venv for now
deactivate

apt update -y

#--------------------------------------------------
# 5) Installing docker and pulling the docker-compose.yml
#--------------------------------------------------

echo "[+] Installing Docker and Docker Compose..."
sudo apt install -y docker.io docker-compose
sudo systemctl enable docker --now



echo "[+] Fetching docker-compose.yml from WebSploit.org..."
wget -O /root/docker-compose.yml https://websploit.org/docker-compose.yml

echo "[+] Starting containers..."
cd /root
docker-compose -f docker-compose.yml up -d

#--------------------------------------------------
# 6) Clone various GitHub repos including mine, SecLists, GitTools, and PayloadsAllTheThings
#--------------------------------------------------
echo "[+] Cloning GitHub repos..."
cd /root
git clone https://github.com/The-Art-of-Hacking/h4cker.git
git clone https://github.com/danielmiessler/SecLists.git
git clone https://github.com/internetwache/GitTools.git
git clone https://github.com/swisskyrepo/PayloadsAllTheThings.git

# IoT firmware exercises for reverse engineering courses
mkdir -p /root/iot_exercises
cd /root/iot_exercises
wget https://github.com/OWASP/IoTGoat/releases/download/v1.0/IoTGoat-raspberry-pi2.img -O firmware1.img
wget https://github.com/santosomar/DVRF/releases/download/v3/DVRF_v03.bin -O firmware2.bin

#--------------------------------------------------
# 7) Install radamsa from source
#--------------------------------------------------
echo "[+] Installing radamsa..."
cd /root
git clone https://gitlab.com/akihe/radamsa.git
cd radamsa
make && make install

#--------------------------------------------------
# 8) Install Sublist3r (example of pip in venv or system-wide)
#     We'll do it in the same venv to avoid PEP 668 issues
#--------------------------------------------------
echo "[+] Installing Sublist3r in the same Python venv..."
cd /root
git clone https://github.com/aboul3la/Sublist3r.git
cd Sublist3r

# Reactivate the venv
source "$VENV_DIR/bin/activate"
pip install -r requirements.txt
deactivate

#--------------------------------------------------
# 9) Install enum4linux-ng
#--------------------------------------------------
cd /root
git clone https://github.com/cddmp/enum4linux-ng
# You can also pip-install it in the venv if you want

#--------------------------------------------------
# 10) If using Parrot, install searchsploit
#--------------------------------------------------
distribution=$(lsb_release -i | awk '{print $NF}')
if [[ "$distribution" == "Parrot" ]]; then
  echo "[+] Installing searchsploit for Parrot..."
  git clone https://github.com/offensive-security/exploitdb.git /opt/exploitdb
  ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
fi



#--------------------------------------------------
# 11) Container info script
#--------------------------------------------------
echo "[+] Installing 'containers' script..."
curl -sSL https://websploit.org/containers.sh > /root/containers.sh
chmod +x /root/containers.sh
mv /root/containers.sh /usr/local/bin/containers

#--------------------------------------------------
# Done
#--------------------------------------------------
echo "
[✔] All done! All tools, apps, and containers have been installed and setup.
Have fun hacking! - Ωr
"
