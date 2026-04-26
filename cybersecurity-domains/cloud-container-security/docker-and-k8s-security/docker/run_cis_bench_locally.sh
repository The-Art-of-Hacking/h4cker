#!/bin/bash
# A simple script to install Chef inspec and the CIS Docker Benchmark InSpec Profile
# Runs on Ubuntu, Debian, Parrot, and Kali Linux
# Author: Omar Santos @santosomar
# version 0.2

#color settings
red=$(tput setaf 1)
green=$(tput setaf 2)
reset=$(tput sgr0)
clear

#welcome screen
echo "🔥🔥🔥 ${green} R U N   C I S   D O C K E R   B E N C H M A R K ${reset} 🔥🔥🔥

Author: Omar Ωr Santos
Twitter: @santosomar
Version: 0.2

${red}This script will automatically install or upgrade InSpec and will run the latest CIS Docker Benchmark from github/dev-sec/cis-docker-benchmark
"
read -n 1 -s -r -p "Press any key to continue the setup..."

#installing InSpec
echo "${green}Installing InSpec"
echo "${reset}========================="

curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

inspec --chef-license=accept

clear 

#running CIS Docker Benchmark directly from GitHub locally
echo "${red}>> Running CIS Docker Benchmark ${reset}locally on $(hostname)"
inspec exec https://github.com/dev-sec/cis-docker-benchmark > cis_benchmark_results.txt

printf -- '\n';
echo "${red}REPORT SUMMARY:"
tail -n 2 cis_benchmark_results.txt

#printing the results
printf -- '\n';
echo "✅ ${reset}The complete results have been stored at: 
${green}$(pwd)/cis_benchmark_results.txt "
