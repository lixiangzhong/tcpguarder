package tcpguarder

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strconv"
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
	Local                  IPPort
	Remote                 IPPort
	Stat                   TCPStat
	TxQueue                int64
	RxQueue                int64
	TimerActive            int
	Jiffies                int64
	RTOTimeouts            int64 //超时重传次数
	UID                    int
	RTO                    int // 单位是clock_t
	CongestionWindow       int //当前拥塞窗口大小
	SlowStartSizeThreshold int //慢启动阈值 ,慢启动阈值大于等于0xFFFF则显示-1
}

/*
TimerActive
  0  no timer is pending  //没有启动定时器
  1  retransmit-timer is pending  //重传定时器
  2  another timer (e.g. delayed ack or keepalive) is pending  //连接定时器、FIN_WAIT_2定时器或TCP保活定时器
  3  this is a socket in TIME_WAIT state. Not all fields will contain data (or even exist)  //TIME_WAIT定时器
  4  zero window probe timer is pending  //持续定时器
*/

func catProcNetTCP() ([]byte, error) {
	b, err := NewCmd("cat /proc/net/tcp").CombinedOutput()
	if err != nil {
		return nil, errors.New(string(b) + err.Error())
	}
	return b, nil
}

func parseProcNetTCP(b []byte) (stats []ConnStat, err error) {
	lines := strings.Split(string(b), "\n")
	for _, line := range lines {
		cols := strings.Fields(line)
		if len(cols) != 17 {
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
		stat.TxQueue, stat.RxQueue, err = parseTxRxQueue(cols[4])
		if err != nil {
			continue
		}
		stat.TimerActive, stat.Jiffies, err = parseTrTm(cols[5])
		if err != nil {
			continue
		}
		stat.RTOTimeouts, err = HexToint64(cols[6])
		if err != nil {
			continue
		}
		stat.UID, err = strconv.Atoi(cols[7])
		if err != nil {
			continue
		}
		stat.RTO, err = strconv.Atoi(cols[12])
		if err != nil {
			continue
		}
		stat.CongestionWindow, err = strconv.Atoi(cols[15])
		if err != nil {
			continue
		}
		stat.SlowStartSizeThreshold, err = strconv.Atoi(cols[16])
		if err != nil {
			continue
		}
		stats = append(stats, stat)
	}
	return
}

func ConnStats() (stats []ConnStat, err error) {
	b, err := catProcNetTCP()
	if err != nil {
		return
	}
	return parseProcNetTCP(b)
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
func parseTxRxQueue(s string) (int64, int64, error) {
	ss := strings.Split(s, ":")
	if len(ss) != 2 {
		return 0, 0, errors.New(s + " bad format: hex TxRxQueue")
	}
	tx, err := HexToint64(ss[0])
	if err != nil {
		return 0, 0, err
	}
	rx, err := HexToint64(ss[1])
	return tx, rx, err
}
func parseTrTm(s string) (int, int64, error) {
	ss := strings.Split(s, ":")
	if len(ss) != 2 {
		return 0, 0, errors.New(s + " bad format: hex TrTm")
	}
	tr, err := HexToint64(ss[0])
	if err != nil {
		return 0, 0, err
	}
	tm, err := HexToint64(ss[1])
	return int(tr), tm, err
}

func HexToint64(s string) (int64, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return 0, err
	}
	var i int64
	switch len(s) {
	case 2:
		i = int64(b[0])
	case 4:
		i = int64(binary.BigEndian.Uint16(b))
	case 8:
		i = int64(binary.BigEndian.Uint32(b))
	}
	return i, nil
}

func NewCmd(s string) *exec.Cmd {
	ss := strings.Fields(s)
	if len(ss) == 1 {
		return exec.Command(ss[0])
	}
	return exec.Command(ss[0], ss[1:]...)
}
