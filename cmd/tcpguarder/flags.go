package main

import (
	"time"

	"github.com/urfave/cli/v2"
)

var (
	FLagTop = cli.IntFlag{
		Name:  "top",
		Usage: "show top list `n`",
		Value: 10,
	}
	FlagPort = cli.IntSliceFlag{
		Name:    "port",
		Aliases: []string{"p"},
		Usage:   "local ports, default all ports,example: -port 80 -port 443",
	}
	FlagKill = cli.IntFlag{
		Name:     "kill",
		Aliases:  []string{"k"},
		Required: true,
		Usage:    "block ip if connection/ip gt `n`",
	}
	FlagWhiteIPFile = cli.StringFlag{
		Name:    "white",
		Aliases: []string{"w"},
		Usage:   "load white ip from `FILE`",
		Value:   "whiteip.txt",
	}
	FlagIPSetName = cli.StringFlag{
		Name:  "ipset",
		Usage: "ipset name",
		Value: "blackhold",
	}
	FlagIPSetTimeout = cli.IntFlag{
		Name:    "timeout",
		Aliases: []string{"t", "time"},
		Usage:   "ipset timeout second",
		Value:   600,
	}
	FlagDuraion = cli.DurationFlag{
		Name:    "duration",
		Aliases: []string{"every", "d"},
		Usage:   "run kill every `duration`",
		Value:   time.Second * 3,
	}
)
