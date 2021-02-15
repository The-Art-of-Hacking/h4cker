#!/usr/bin/env python3
# A script to perform a quick OSINT recon for a given domains
# This is an example and work in progress

import os , sys , time , requests , random
from googlesearch import search
from termcolor import colored, cprint
from http import cookiejar
from urllib.parse import urlparse
from plugins import pasting

Subdomains = []

def SubdomainFilter(URL):
    Parsed = urlparse(URL); Scheme = Parsed.scheme; Host = Parsed.netloc; URL = Scheme + "://" + Host + "/"
    if URL not in Subdomains:
        print(URL); Subdomains.append(URL)

if os.path.exists("alpha.txt"):
  print("")
  Qupdate = requests.get('https://raw.githubusercontent.com/The-Art-of-Hacking/h4cker/osint/quick_recon/qrecon_update.txt') #Quantom
  Qupdate.status_code
  if Qupdate.status_code == 200:
   print(colored ('Cheking Update...' ,'white'))
   print(colored(Qupdate.text , 'green'))
   time.sleep(3) #
  elif Qupdate.status_code == 404:
   print(colored ('Cheking Update...' ,'white'))
   print(colored ('Update Available ' ,'red'))
   print(colored ('See https://github.com/The-Art-of-Hacking/h4cker/tree/master/osint' ,'red'))
   print(colored ('Resuming...' ,'red'))
   print("")
  time.sleep(3) #

  f = open('alpha.txt', 'r')
  alpha = f.read()
  print(colored (alpha,'yellow'))


else:
  print("")
  print(colored ('Please Run the quick_recon Script in the Main Directory' ,'red'))
  print(colored ('First: cd quick_recon ' ,'red'))
  print(colored ('Then : python3 quick_recon.py' ,'red'))
  print(colored ('Exiting...' ,'red'))
  time.sleep(5)
  exit()

banner1 = """
Quick OSINT Recon of a given domain
̿з=(◕_◕)=ε
                              """
print (banner1)

#--------------------------------------------------------------------------------#
class BlockAll(cookiejar.CookiePolicy):
    return_ok = set_ok = domain_return_ok = path_return_ok = lambda self, *args, **kwargs: False
    netscape = True
    rfc2965 = hide_cookie2 = False
TLD = ["com","com.tw","co.in"]
beta  = random.choice(TLD)
s = requests.Session()
s.cookies.set_policy(BlockAll())

#--------------------------------------------------------------------------------#

key  = input (colored('[+] Set Target (site.com) : ', 'white' ))#Key
file = open("quick_recon.config", "w")
file.write(key)
file.close()
#V2
#V2
print("")
print(colored ('[>] Looking For Subdomains...' ,'green'))
query = "site:" + key + " -www." + key                            #SubTech1
for gamma in search(query, tld=beta, num=30 , stop=60 , pause=2):
    SubdomainFilter(URL=gamma)
query = "site:*." + key                                           #SubTech2
for gamma in search(query, tld=beta, num=30 , stop=60 , pause=2):
    SubdomainFilter(URL=gamma)
print("")

if os.path.exists(".google-cookie"):
 os.remove(".google-cookie")

print(colored ('[>] Looking For Sub-Subdomains...' ,'green'))
query = "site:*.*." + key
for gamma in search(query, tld=beta, num=30 , stop=60 , pause=2):
    SubdomainFilter(URL=gamma)
print("")

if os.path.exists(".google-cookie"):
 os.remove(".google-cookie")


print(colored ('[>] Looking For Login/Signup Pages...' ,'green'))
query = "inurl:login site:" + key                                        #LogTech1
for gamma in search(query, tld=beta, num=30 , stop=60 , pause=2):
    print("" + gamma)
query = "site:" + key + " inurl:signup | inurl:register | intitle:Signup" #LogTech2
for gamma in search(query, tld=beta, num=30 , stop=60 , pause=2):
    print("" + gamma)
print ("")
if os.path.exists(".google-cookie"):
 os.remove(".google-cookie")

# Sleeping for 60s to Avoid Google Block
print(colored ('[!] 20s Sleep to avoid Google Block' ,'yellow'))
time.sleep(21) # ; )
print(colored ('[!] Switching Google TLDs...' ,'yellow'))
TLD = ["co.ma","dz","ru","ca"]
zolo  = random.choice(TLD)
print("")
#ok

print(colored ('[>] Looking For Directory Listing...' ,'green')) #DirListing
query = "site:" + key + " intitle:index of"
for gamma in search(query, tld=zolo, num=10 , stop=60 , pause=2):
    print("" + gamma)
print ("")
if os.path.exists(".google-cookie"):
 os.remove(".google-cookie")

print(colored ('[>] Looking For Public Exposed Documents...' ,'green')) #Docs
query = "site:" + key + " ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv"
for gamma in search(query, tld=zolo, num=30 , stop=60 , pause=2):
    print("" + gamma)
print ("")
if os.path.exists(".google-cookie"):
 os.remove(".google-cookie")


print(colored ('[>] Looking For WordPress Entries...' ,'green')) #WP
query = "site:" + key + " inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download"
for gamma in search(query, tld=zolo, num=30 , stop=60 , pause=2):
    print("" + gamma)
print ("")
if os.path.exists(".google-cookie"):
 os.remove(".google-cookie")
