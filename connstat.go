package tcpguarder

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
)

type TCPStat string

const (
	ESTABLISHED TCPStat = "ESTABLISHED"
	SYN_SENT    TCPStat = "SYN_SENT"
	SYN_RECV    TCPStat = "SYN_RECV"
	FIN_WAIT1   TCPStat = "FIN_WAIT1"
	FIN_WAIT2   TCPStat = "FIN_WAIT2"
	TIME_WAIT   TCPStat = "TIME_WAIT"
	CLOSE       TCPStat = "CLOSE"
	CLOSE_WAIT  TCPStat = "CLOSE_WAIT"
	LAST_ACK    TCPStat = "LAST_ACK"
	LISTEN      TCPStat = "LISTEN"
	CLOSING     TCPStat = "CLOSING"
	MAX_STATES  TCPStat = "MAX_STATES"
)

var TCPStatCodeString = map[string]TCPStat{
	"01": ESTABLISHED,
	"02": SYN_SENT,
	"03": SYN_RECV,
	"04": FIN_WAIT1,
	"05": FIN_WAIT2,
	"06": TIME_WAIT,
	"07": CLOSE,
	"08": CLOSE_WAIT,
	"09": LAST_ACK,
	"0A": LISTEN,
	"0B": CLOSING,
	"0C": MAX_STATES,
}

type IPPort struct {
	IP   net.IP
	Port uint16
}

func (i IPPort) String() string {
	return fmt.Sprintf("%s:%v", i.IP, i.Port)
}

type ConnStat struct {
	Local  IPPort
	Remote IPPort
	Stat   TCPStat
}

func ConnStats() (stats []ConnStat, err error) {
	b, err := NewCmd("cat /proc/net/tcp").CombinedOutput()
	if err != nil {
		fmt.Println(string(b))
		return nil, err
	}
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		cols := strings.Fields(line)
		if len(cols) < 4 {
			continue
		}
		if cols[0] == "sl" {
			continue
		}
		local, err := parseHexIPPort(cols[1])
		if err != nil {
			continue
		}
		remote, err := parseHexIPPort(cols[2])
		if err != nil {
			continue
		}
		var stat ConnStat
		stat.Local = local
		stat.Remote = remote
		stat.Stat = TCPStatCodeString[cols[3]]
		if stat.Stat == "" {
			continue
		}
		stats = append(stats, stat)
	}
	return
}

func parseHexIPPort(s string) (ip IPPort, err error) {
	ss := strings.Split(s, ":")
	if len(ss) != 2 {
		return ip, errors.New(s + " bad format: hex ip port")
	}
	ip.IP, err = hex.DecodeString(ss[0])
	if err != nil {
		return ip, err
	}
	l := len(ip.IP)
	for i := 0; i < l/2; i++ {
		ip.IP[i], ip.IP[l-i-1] = ip.IP[l-i-1], ip.IP[i]
	}
	b, err := hex.DecodeString(ss[1])
	if err != nil {
		return ip, err
	}
	ip.Port = binary.BigEndian.Uint16(b)
	return
}

func NewCmd(s string) *exec.Cmd {
	ss := strings.Fields(s)
	if len(ss) == 1 {
		return exec.Command(ss[0])
	}
	return exec.Command(ss[0], ss[1:]...)
}
