# SSRF Test Script
[This script](https://github.com/The-Art-of-Hacking/h4cker/blob/master/web_application_testing/ssrf_ywing.py) is a utility to test for potential Server Side Request Forgery (SSRF) vulnerabilities in a Grafana instance through Prometheus.

## Author
This script was originally authored by @RandomRobbieBF; then slightly modified by Omar Santos to add additional documentation and instructions.

## Pre-requisites

- Python 3
- Python `requests` library

## Usage

This script requires command line arguments to run. Here's a list of all arguments:

- `-s` or `--session`: The session cookie value. (Default: `"9765ac114207245baf67dfd2a5e29f3a"`)
- `-u` or `--url`: The URL of the host to check for SSRF. (Default: `"http://8t2s8yx5gh5nw0z9bd3atkoprgx6lv.burpcollaborator.net"` or you can use interact.sh)
- `-H` or `--host`: The Grafana host URL. (Required)
- `-U` or `--username`: The Grafana username. (Optional)
- `-P` or `--password`: The Grafana password. (Optional)
- `-p` or `--proxy`: A proxy for debugging. (Optional)

To run the script, navigate to the script's directory and use the following command:

```
python ssrf_ywing.py -H "http://victim_host" -u cf3jbjp2vtc0000ey330g8t3f3cyyyyyb.oast.fun
```

Replace `cf3jbjp2vtc0000ey330g8t3f3cyyyyyb.oast.fun` with the URL of interact.sh or Burp Collaborator. 

## Note

- This script operates under the assumption that the target host permits insecure SSL connections. This assumption is premised on the fact that the containers in WebSploit Labs are configured to run over HTTP, reflecting their sole purpose of serving as controlled environments for testing and learning.
- The SSRF exploit attempted by this script does not follow redirects.
