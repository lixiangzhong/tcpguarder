package tcpguarder

import "sort"

func Top(dstports []int) ([]CountItem, error) {
	allport := len(dstports) == 0
	ipn := make(map[string]int)
	stats, err := ConnStats()
	if err != nil {
		return nil, err
	}
	for _, c := range stats {
		if c.Stat == LISTEN {
			continue
		}
		if allport {
			ipn[c.Remote.IP.String()]++
			continue
		}
		for _, port := range dstports {
			if c.Local.Port == uint16(port) {
				ipn[c.Remote.IP.String()]++
				break
			}
		}
	}
	iptop := make([]CountItem, 0)
	for k, v := range ipn {
		iptop = append(iptop, CountItem{
			Key: k,
			N:   v,
		})
	}
	sort.Slice(iptop, func(i, j int) bool {
		return iptop[i].N > iptop[j].N
	})
	return iptop, nil
}

type CountItem struct {
	Key string
	N   int
}
