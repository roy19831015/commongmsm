package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	layers_ex "gmsm/pcapng/layers"
)

var layerTypeGMTLS gopacket.LayerType

func main() {
	layerTypeGMTLS = gopacket.RegisterLayerType(0x101, gopacket.LayerTypeMetadata{Name: "GMTLSv1", Decoder: gopacket.DecodeFunc(layers_ex.DecodeGMTLS)})

	fileName := "d:\\sm2.pcapng"
	handle, err := pcap.OpenOffline(fileName)
	if err != nil {
		return
	}
	source := gopacket.NewPacketSource(handle, handle.LinkType())
	i := 0
	for packet := range source.Packets() {
		i++
		fmt.Printf("第%d个包：\n", i)
		printNetworkInfo(packet)
		printTransportInfo(packet)
		printLinkInfo(packet)
		printApplicationInfo(packet)
	}
}

func printNetworkInfo(packet gopacket.Packet) {
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		fmt.Printf("网络层信息如下：%s\n", networkLayer.NetworkFlow().String())
	}
}

func printTransportInfo(packet gopacket.Packet) {
	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		fmt.Printf("传输层信息如下：%s\n", transportLayer.TransportFlow().String())
	}
}

func printLinkInfo(packet gopacket.Packet) {
	linkLayer := packet.LinkLayer()
	if linkLayer != nil {
		fmt.Printf("链接层信息如下：%s\n", linkLayer.LinkFlow().String())
	}
}

func printApplicationInfo(packet gopacket.Packet) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("应用层信息如下：")
		gmtlsLayer := gopacket.NewPacket(applicationLayer.Payload(),
			layerTypeGMTLS,
			gopacket.DecodeOptions{Lazy: true, NoCopy: true})
		fmt.Printf(gmtlsLayer.String())
	}
}
