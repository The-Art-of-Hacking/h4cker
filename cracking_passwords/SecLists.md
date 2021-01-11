# Daniel Miessler's SecLists is the Bomb!

[SecLists](https://github.com/danielmiessler/SecLists) include numerous wordlists that can be used for web application discovery, fuzzing, password cracking with millions of passwords from breaches, default passwords, pattern-matching, payloads, usernames, web-shells, and more.

You can install it using the following methods:

**Zip**
```
wget -c https://github.com/danielmiessler/SecLists/archive/master.zip -O SecList.zip \
  && unzip SecList.zip \
  && rm -f SecList.zip
```

**Git (Small)**
```
git clone --depth 1 https://github.com/danielmiessler/SecLists.git
```

**Git (Complete)**
```
git clone https://github.com/danielmiessler/SecLists.git
```

**Kali Linux** ([Tool Page](https://tools.kali.org/password-attacks/seclists))
```
apt -y install seclists
```


