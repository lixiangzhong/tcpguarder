##  tcpguarder

 Inspiration from https://github.com/jagerzhang/CCKiller

```shell script
go get github.com/lixiangzhong/tcpguarder/cmd/tcpguarder
```

```shell script
[root@localhost ~]# tcpguarder -h
NAME:
   tcpguarder - tcpguarder

USAGE:
   tcpguarder [global options] command [command options] [arguments...]

COMMANDS:
   run       block ip auto
   china     create china ipset
   notchina  create not-china ipset
   help, h   Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --ipset value                            ipset name (default: "blackhold")
   --port value, -p value                   local ports, default all ports,example: -port 80 -port 443
   --timeout value, -t value, --time value  ipset timeout second (default: 600)
   --top n                                  show top list n (default: 10)
   --white FILE, -w FILE                    load white ip from FILE (default: "whiteip.txt")
   --help, -h                               show help (default: false)
```

```shell script
# Display by highest IP connection number

[root@localhost ~]# tcpguarder
127.0.0.1	5
10.10.0.1	2

total
ip: 2 tcp: 7
```


```shell script
# Automatically block IPs with connections greater than 200
# Program will block forever

[root@localhost ~]# tcpguarder run -k=200
please confirm the following iptable is in effect
iptables -I INPUT -p tcp -m set --match-set blackhold src -j DROP
load white ip file: whiteip.txt
2020/03/20 17:51:26 open whiteip.txt: no such file or directory
white ip num: 0
local ip: 127.0.0.1
local ip: 10.10.1.244
white ip num: 2
every 3s kill if conn/ip >= 200
```


```shell script
# Count every 10 seconds, and block IPs with connections greater than 200

[root@localhost ~]# ./tcpguarder run -k=200 -every=10s
```

```shell script
# Statistics every 3 seconds to connect to ports 80 and 443, and block IPs with more than 100 links
# 每3秒统计连接到80和443端口,并且屏蔽链接数大于100的IP

[root@localhost ~]# ./tcpguarder run -k=100 -port 80 -port 443
```


```shell script
# Create an ipset without a Chinese IP

[root@localhost ~]# tcpguarder notchina
please confirm the following iptable is in effect
iptables -I INPUT -p tcp -m set --match-set notchina src -j DROP
iptables -I INPUT -p tcp -m set --match-set notchina src -m multiport --dports 80,443 -j DROP
```

```shell script
# Create an ipset containing only Mainland China IP

[root@localhost ~]# tcpguarder china
please confirm the following iptable is in effect
iptables -I INPUT -p tcp -m set --match-set china src -j DROP
iptables -I INPUT -p tcp -m set --match-set china src -m multiport --dports 80,443 -j DROP
```