# beats-output-remote-syslog

Simple Elastic Beats output to remote syslog plugin;  
uses [go-syslog](https://github.com/hashicorp/go-syslog) from Hashicorp

# Configuration options

- `host`: hostname of remote syslog collector (string, default: `127.0.0.1`)
- `port`: port (integer, default: `514`)
- `proto`: protocol udp or tcp (string, default: `udp`)  
   see also [golang net.Dial](https://golang.org/pkg/net/#Dial) documentation
- `facility`: syslog facility (string, default `LOCAL0`)
- `severity`: syslog severity (string, default `WARNING`)

# Building

- clone this repo
- clone Elastic Beats repository, get dependencies
- apply patch on Beats repository
- build filebeat

```bash
cd
go get github.com/remil1000/beats-output-remote-syslog
go get github.com/elastic/beats
cd ${GOPATH:-go}/src/github.com/remil1000/beats-output-remote-syslog
go get ./...
cd ${GOPATH:-go}/src/github.com/elastic/beats
go get ./...
patch -p1 < ../../../github.com/remil1000/beats-output-remote-syslog/*.patch
cd filebeat
make
```

# Example configuration

```yaml
filebeat.prospectors:
- type: log
  ignore_older: 2h
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/syslog
#output.console:
#  pretty: true
output.syslog:
  host: "127.0.0.1"  # default 127.0.0.1
  severity: "CRIT"   # default warning
  facility: "local4" # default local0
  port: 514          # default 514
  proto: "udp"       # default udp
  codec.format:
    string: 'file:"%{[source]}" message:"%{[message]}"'
```

## Supported severity

- EMERG
- ALERT
- CRIT
- ERR
- WARNING
- NOTICE
- INFO
- DEBUG

## Supported facility

- KERN
- USER
- MAIL
- DAEMON
- AUTH
- SYSLOG
- LPR
- NEWS
- UUCP
- CRON
- AUTHPRIV
- FTP
- LOCAL0
- LOCAL1
- LOCAL2
- LOCAL3
- LOCAL4
- LOCAL5
- LOCAL6
- LOCAL7

