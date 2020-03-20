package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lixiangzhong/tcpguarder"
	"github.com/lixiangzhong/tcpguarder/cmd/tcpguarder/iplib"
	"github.com/urfave/cli/v2"
)

var (
	whiteip = make(map[*net.IPNet]bool)
)

func main() {
	app := cli.NewApp()
	app.Name = "tcpguarder"
	app.Usage = "tcpguarder"
	app.EnableBashCompletion = true
	app.Flags = []cli.Flag{
		&FLagTop, &FlagPort, &FlagIPSetName, &FlagIPSetTimeout, &FlagWhiteIPFile,
	}
	app.Before = showPortsAction
	app.Action = ShowTopAction
	app.Commands = []*cli.Command{
		&cli.Command{
			Name:        "run",
			Usage:       "block ip auto",
			Description: "example: run -kill=200",
			Before:      BeforeKill,
			Action:      KillAction,
			Flags:       []cli.Flag{&FlagPort, &FlagKill, &FlagIPSetName, &FlagIPSetTimeout, &FlagWhiteIPFile, &FlagDuraion},
		},
		&cli.Command{
			Name:   "china",
			Usage:  "create china ipset",
			Action: CreateChinaIPSet,
		},
		&cli.Command{
			Name:   "notchina",
			Usage:  "create not-china ipset",
			Action: CreateNotChinaIPSet,
		},
	}
	sort.Sort(cli.FlagsByName(app.Flags))
	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func ShowTopAction(c *cli.Context) (err error) {
	total := 0
	ss, err := tcpguarder.Top(c.IntSlice("port"))
	if err != nil {
		return
	}
	for i, v := range ss {
		total += v.N
		if i > c.Int("top") {
			continue
		}
		fmt.Printf("%v\t%v\n", v.Key, v.N)
	}
	fmt.Println("\ntotal\nip:", len(ss), "tcp:", total)
	return
}

func KillAction(c *cli.Context) error {
	ports := c.IntSlice("port")
	duraion := c.Duration("duration")
	tk := time.NewTicker(duraion)
	defer tk.Stop()
	kill := c.Int("kill")
	fmt.Printf("every %v kill if conn/ip >= %v\n", duraion, kill)
	do := func() {
		ss, err := tcpguarder.Top(ports)
		if err != nil {
			log.Println(err)
			return
		}
		for _, v := range ss {
			if v.N >= kill {
				if isWhiteIP(v.Key) {
					continue
				}
				if blockip(c, v.Key) {
					log.Println("block", v.Key, "tcp", v.N)
				}
				continue
			}
			return
		}
	}
	do()
	for range tk.C {
		do()
	}
	return nil
}

func isWhiteIP(ip string) bool {
	for ipnet := range whiteip {
		if ipnet.Contains(net.ParseIP(ip)) {
			return true
		}
	}
	return false
}

func showPortsAction(c *cli.Context) error {
	ports := c.IntSlice("port")
	if len(ports) > 0 {
		fmt.Println("local ports:", ports)
	}
	return nil
}

func BeforeKill(c *cli.Context) error {
	showPortsAction(c)
	name := c.String("ipset")
	timeout := c.Int("timeout")
	err := createipset(name, timeout)
	if err == nil {
		fmt.Printf("ipset create %v hash:ip timeout %v\n", name, timeout)
	}
	ports := c.IntSlice("port")
	fmt.Println("please confirm the following iptable is in effect")
	if len(ports) > 0 {
		fmt.Printf("iptables -I INPUT -p tcp -m set --match-set %v src -m multiport --dports %v -j DROP\n", name, jointostring(ports, ","))
		fmt.Println("or")
	}
	fmt.Printf("iptables -I INPUT -p tcp -m set --match-set %v src -j DROP\n", name)
	fmt.Println("load white ip file:", c.String("white"))
	b, err := ioutil.ReadFile(c.String("white"))
	if err != nil {
		log.Println(err)
	}
	for _, v := range strings.Fields(string(b)) {
		ip := net.ParseIP(v)
		if ip.To4() != nil {
			v += "/32"
		}
		if _, ipnet, err := net.ParseCIDR(v); err == nil {
			whiteip[ipnet] = true
		}
	}
	fmt.Println("white ip num:", len(whiteip))
	for _, v := range LocalIPList() {
		v = v.To4()
		if v == nil {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(v.String() + "/32"); err == nil {
			fmt.Println("local ip:", v)
			whiteip[ipnet] = true
		}
	}
	fmt.Println("white ip num:", len(whiteip))
	return nil
}

func jointostring(elems []int, sep string) string {
	s := make([]string, 0)
	for _, v := range elems {
		s = append(s, strconv.Itoa(v))
	}
	return strings.Join(s, sep)
}

func createipset(name string, timeout int) error {
	return tcpguarder.NewCmd(fmt.Sprintf("ipset create %v hash:ip timeout %v", name, timeout)).Run()
}

func blockip(c *cli.Context, ip string) bool {
	return tcpguarder.NewCmd(fmt.Sprintf("ipset add %v %v", c.String("ipset"), ip)).Run() == nil
}

func CreateChinaIPSet(c *cli.Context) error {
	fmt.Println("please confirm the following iptable is in effect")
	fmt.Println("iptables -I INPUT -p tcp -m set --match-set china src -j DROP")
	fmt.Println("iptables -I INPUT -p tcp -m set --match-set china src -m multiport --dports 80,443 -j DROP")
	err := tcpguarder.NewCmd("ipset create china hash:net").Run()
	if err != nil {
		log.Println(err)
	}
	b, err := iplib.Asset("china-cidr.txt")
	if err != nil {
		return err
	}
	for _, v := range strings.Fields(string(b)) {
		tcpguarder.NewCmd(fmt.Sprintf("ipset add china %v", v)).Run()
	}
	return nil
}

func CreateNotChinaIPSet(c *cli.Context) error {
	fmt.Println("please confirm the following iptable is in effect")
	fmt.Println("iptables -I INPUT -p tcp -m set --match-set notchina src -j DROP")
	fmt.Println("iptables -I INPUT -p tcp -m set --match-set notchina src -m multiport --dports 80,443 -j DROP")
	err := tcpguarder.NewCmd("ipset create notchina hash:net").Run()
	if err != nil {
		log.Println(err)
	}
	b, err := iplib.Asset("not-china-cidr.txt")
	if err != nil {
		return err
	}
	for _, v := range strings.Fields(string(b)) {
		tcpguarder.NewCmd(fmt.Sprintf("ipset add notchina %v", v)).Run()
	}
	return nil
}

func LocalIPList() (iplist []net.IP) {
	itfs, err := net.Interfaces()
	if err != nil {
		log.Println(err)
		return nil
	}
	for _, itf := range itfs {
		if itf.Flags&net.FlagPointToPoint == net.FlagPointToPoint {
			continue
		}
		addrs, err := itf.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if ok {
				iplist = append(iplist, ipnet.IP)
			}
		}
	}
	return
}
