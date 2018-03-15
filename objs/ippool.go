package objs

import (
	"net"
	"github.com/devplayg/golibs/network"
)


type IpPool struct {
	IppoolId int
	FolderId int
	SensorId int
	IpCidr   string
	Name     string
	IPNet    net.IPNet
	HostCount int

}

func (a IpPool) Network() net.IPNet {
	return a.IPNet
}
//
//type IpPoolList []*IpPool
//
//func (a IpPoolList) Len() int           { return len(a) }
//func (a IpPoolList) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
//func (a IpPoolList) Less(i, j int) bool { return a[i].HostCount < a[j].HostCount }

func (a *IpPool) UpdateIpNet() error {
	_, ipNet, _ := net.ParseCIDR(a.IpCidr)
	a.IPNet = *ipNet

	cidr, _ := a.IPNet.Mask.Size()
	a.HostCount =  network.GetNetworkHostCount(cidr)

	return nil
}
//
//func NewIpPool(ippool *IpPool) cidranger.RangerEntry {
//	_, ipNet, _ := net.ParseCIDR(ippool.IpCidr)
//	return &IpPool{
//		SensorId: ippool.SensorId,
//		FolderId: ippool.FolderId,
//		IppoolId: ippool.IppoolId,
//		IpCidr:   ippool.IpCidr,
//		Name:     ippool.Name,
//		IPNet:    *ipNet,
//	}
//}
