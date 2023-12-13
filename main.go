package main

import (
	"fmt"
	"github.com/dreadl0ck/gopcap"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"io"
	"net"
)

type suspect struct {
	ipPack *layers.IPv4
	number int
}

func main() {
	filename := "<path/to/filename.pcap>"
	reqSrcIP := net.ParseIP("169.254.0.1")
	reqDstIP := net.ParseIP("169.254.0.2")
	innerPayload := layers.LayerTypeUDP

	r, err := gopcap.Open(filename)
	if err != nil {
		fmt.Printf("gopcap error: %v", err.Error())
		return
	}
	defer func() { _ = r.Close() }()

	suspectList := nsmParser(filename, reqSrcIP, reqDstIP, innerPayload)
	//suspectList := bareVPPParser(filename, reqSrcIP, reqDstIP, innerPayload)

	for _, s := range suspectList {
		fmt.Println(s.number)
	}
	fmt.Printf("--- TOTAL suspectList: %v ---\n", len(suspectList))
}

func nsmParser(pcapFileName string, srcIP, dstIP net.IP, payloadLayer gopacket.LayerType) (suspectList []*suspect) {
	r, err := gopcap.Open(pcapFileName)
	if err != nil {
		fmt.Printf("gopcap error: %v", err.Error())
		return
	}
	defer func() { _ = r.Close() }()

	counter := 0
	for {
		counter++
		_, data1, err := r.ReadNextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		p := gopacket.NewPacket(data1, layers.LayerTypeEthernet, gopacket.Default)
		if p == nil {
			fmt.Println("NewPacket error: nil")
			continue
		}

		outUDPPointer := p.Layer(layers.LayerTypeUDP)
		if outUDPPointer == nil {
			continue
		}
		outUDP, _ := outUDPPointer.(*layers.UDP)
		if outUDP.DstPort != 4789 {
			continue
		}

		pVXLAN := gopacket.NewPacket(outUDP.Payload, layers.LayerTypeVXLAN, gopacket.Default)
		if pVXLAN == nil {
			fmt.Println("pVXLAN NewPacket error: nil")
			continue
		}

		if pVXLAN.Layer(payloadLayer) == nil {
			continue
		}

		inIPPointer := pVXLAN.Layer(layers.LayerTypeIPv4)
		if inIPPointer == nil {
			continue
		}

		inIP, _ := inIPPointer.(*layers.IPv4)

		if !inIP.SrcIP.Equal(srcIP) && !inIP.SrcIP.Equal(dstIP) {
			continue
		}

		if inIP.SrcIP.Equal(srcIP) {
			suspectList = append(suspectList, &suspect{
				ipPack: inIP,
				number: counter,
			})
		}
		if inIP.SrcIP.Equal(dstIP) {
			if len(suspectList) > 0 {
				suspectList = suspectList[:len(suspectList)-1]
			}
		}
	}
	return
}

func bareVPPParser(pcapFileName string, srcIP, dstIP net.IP, payloadLayer gopacket.LayerType) (suspectList []*suspect) {
	r, err := gopcap.Open(pcapFileName)
	if err != nil {
		fmt.Printf("gopcap error: %v", err.Error())
		return
	}
	defer func() { _ = r.Close() }()

	counter := 0
	for {
		counter++
		_, data1, err := r.ReadNextPacket()
		if err != nil {
			if err == io.EOF {
				break
			}
			panic(err)
		}

		p := gopacket.NewPacket(data1, layers.LayerTypeEthernet, gopacket.Default)
		if p == nil {
			fmt.Println("NewPacket error: nil")
			continue
		}

		player := p.Layer(payloadLayer)
		if player == nil {
			continue
		}

		ipLayerPointer := p.Layer(layers.LayerTypeIPv4)
		if ipLayerPointer == nil {
			continue
		}

		ipLayer, _ := ipLayerPointer.(*layers.IPv4)

		if !ipLayer.SrcIP.Equal(srcIP) && !ipLayer.SrcIP.Equal(dstIP) {
			continue
		}

		if ipLayer.SrcIP.Equal(srcIP) {
			suspectList = append(suspectList, &suspect{
				ipPack: ipLayer,
				number: counter,
			})
		}
		if ipLayer.SrcIP.Equal(dstIP) {
			if len(suspectList) > 0 {
				suspectList = suspectList[:len(suspectList)-1]
			}
		}
	}
	return
}
