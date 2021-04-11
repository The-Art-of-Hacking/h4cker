#!/bin/bash
# A simple script to install Chef inspec and the CIS Docker Benchmark InSpec Profile
# Runs on Ubuntu, Debian, Parrot, and Kali Linux
# Author: Omar Santos @santosomar
# version 0.1

red=$(tput setaf 1)
green=$(tput setaf 2)
reset=$(tput sgr0)

echo "${green}Installing InSpec"
echo "${reset}========================="

curl https://omnitruck.chef.io/install.sh | sudo bash -s -- -P inspec

echo "${red} Running CIS Docker Benchmark ${reset} locally on $(hostname)"
inspec exec https://github.com/dev-sec/cis-docker-benchmark