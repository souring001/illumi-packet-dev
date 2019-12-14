package main

import (
    "fmt"
    "flag"
    "strings"
    "time"
    "log"
    "os"
    "net"
    "errors"
    "github.com/jgarff/rpi_ws281x/golang/ws2811"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

type layerMeta struct{
    color uint32
    show bool
}

const (
    ipv4Len    = 4
    pin        = 18     // GPIO
    series     = 12     // length of trail
    count      = 144    // number of LEDs
    brightness = 50     // max 255
)

var (
    colors = []uint32{
        // GRB color
        0xFFFFFF, //0 White others
        0x880000, //1 Green
        0x00FF00, //2 Red Anomaly
        0x0000FF, //3 Blue TCP
        0x0066cc, //4 Purple ARP
        0x33FF99, //5 Pink ICMP
        0xFFFF00, //6 Yellow UDP
        0x88FF00, //7 Orange IGMP
        0xFF00FF, //8 Cyan DHCP
        0xFF0000, //9 Lime DNS
        0x888888, //10 GRAY
    }
    speed        = 4    // speed of flowing packet
    debug       = flag.Bool("debug", true, "print packet details")
    showip       = flag.Bool("ipaddr", false, "display ip address")
    xarp         = flag.Bool("xarp", false, "disable arp")
    xtcp         = flag.Bool("xtcp", false, "disable tcp")
    xudp         = flag.Bool("xudp", false, "disable udp")
    snapshotLen  = int32(1024)
    promiscuous  = false
    timeout      = 50 * time.Millisecond
    device string
    layerMap = map[string]layerMeta{
        "ARP":      layerMeta{ color: colors[7], show: true },
        "ICMP":     layerMeta{ color: colors[5], show: true },
        "TCP":      layerMeta{ color: colors[3], show: true },
        "UDP":      layerMeta{ color: colors[6], show: true },
        "IGMP":     layerMeta{ color: colors[4], show: true },
        "DNS":      layerMeta{ color: colors[9], show: true },
        "DHCP":     layerMeta{ color: colors[8], show: true },
        "Anomaly":  layerMeta{ color: colors[2], show: true },
        "Others":   layerMeta{ color: colors[0], show: true },
    }
)

func main() {
    // option flag
    flag.String(&device, "device", "eth0", "set network interface")
    flag.Parse()

    meta := layerMap["ARP"]
    meta.show = *xarp
    layerMap["ARP"] = meta

    meta := layerMap["TCP"]
    meta.show = *xtcp
    layerMap["TCP"] = meta

    meta := layerMap["UDP"]
    meta.show = *xudp
    layerMap["UDP"] = meta

    // set ipAddress
    ipAddr, err := externalIP()
	if err != nil { log.Fatal(err) }
    if *debug { fmt.Println("IP address is:", ipAddr) }

    // Open device
    handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
    if err != nil { log.Fatal(err) }
    defer handle.Close()

    // Initialize LED strip
    errl := ws2811.Init(pin, count, brightness)
    if errl != nil { log.Fatal(errl) }
    defer ws2811.Fini()
    if *debug { fmt.Println("Press Ctr-C to quit.") }

    led := make([]uint32, count)

    if *showip {
        showIPAddress(led, ipAddr)
    }else{
        // Use the handle as a packet source to process all packets
        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        if *debug { fmt.Println("Start capturing...") }

        for packet := range packetSource.Packets() {

            // Direction of the packet
            reverse := true
            if net := packet.NetworkLayer(); net != nil {
                src, _ := net.NetworkFlow().Endpoints()
                if strings.Contains(src.String(), ipAddr) {
                    reverse = false
                }
            }

            packetName := categorizePacket(packet)
            fmt.Println(packetName)
            layerMeta := layerMap[packetName]

            if *debug {
                fmt.Println(packetName)
                fmt.Println(packet)
            }
            if layerMeta.show {
                castPacket(led, series, layerMeta.color, reverse)
            }

            // Anomary detection
            // if isAnomaly(packet) {
            //     if *debug {
            //         fmt.Println("ANOMALY")
            //     }
            //     castPacket(led, series, colors[2], reverse)
            // }else if lldp := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldp != nil {
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("LLDP")
            //     }
            //     castPacket(led, series, colors[0], reverse)
            // }else if dns := packet.Layer(layers.LayerTypeDNS); dns != nil {
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("DNS")
            //     }
            //     castPacket(led, series, colors[9], reverse)
            // }else if icmpv4 := packet.Layer(layers.LayerTypeICMPv4); icmpv4 != nil {
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("ICMPv4")
            //     }
            //     castPacket(led, series, colors[5], reverse)
            // }else if icmpv6 := packet.Layer(layers.LayerTypeICMPv6); icmpv6 != nil {
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("ICMPv6")
            //     }
            //     castPacket(led, series, colors[5], reverse)
            // }else if dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4); dhcpv4 != nil {
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("DHCPv4")
            //     }
            //     castPacket(led, series, colors[8], reverse)
            // }else if arp := packet.Layer(layers.LayerTypeARP); arp != nil{
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("ARP")
            //     }
            //     if !*xarp{
            //         castPacket(led, series, colors[7], reverse)
            //     }
            // }else if igmp := packet.Layer(layers.LayerTypeIGMP); igmp != nil {
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("IGMP")
            //     }
            //     castPacket(led, series, colors[4], reverse)
            // }else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil{
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("UDP")
            //     }
            //     if !*xudp{
            //         castPacket(led, series, colors[6], reverse)
            //     }
            // }else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil{
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("TCP")
            //     }
            //     if !*xtcp{
            //         castPacket(led, series, colors[3], reverse)
            //     }
            // }else{
            //     if *debug {
            //         fmt.Println(packet)
            //         fmt.Println("OTHERS")
            //     }
            //     castPacket(led, series, colors[0], reverse)
            // }
        }

    }
}

func reverseLeds(led []uint32) {
    for i, j := 0, len(led)-1; i < j; i, j = i+1, j-1 {
        led[i], led[j] = led[j], led[i]
    }
}

func initLeds(led []uint32) {
    for i, _ := range led {
        led[i] = 0
    }
}

func castPacket(led []uint32, k int, color uint32,reverse bool) {
    for i := -(k-1); i < len(led)+series+speed; i += speed {
        initLeds(led)

        for j := 0; j < k; j++ {
            if t := i + j; 0 <= t && t < len(led) {
                // packet color gradiation
                g := (((color & 0xFF0000) >> 16) * uint32(j+1) / uint32(k)) << 16
                r := (((color & 0x00FF00) >> 8)* uint32(j+1) / uint32(k)) << 8
                b := (color & 0x0000FF)* uint32(j+1) / uint32(k)
                led[t] = g|r|b
            }
        }

        if reverse {
            reverseLeds(led)
        }

        setLeds(led)
        err := ws2811.Render()
        if err != nil {
            ws2811.Clear()
            fmt.Println("Error during wipe " + err.Error())
            os.Exit(-1)
        }
    }
}

func setLeds(led []uint32) {
	for i := 0; i < count; i++ {
		ws2811.SetLed(i, led[i])
	}
}

func isAnomaly(packet gopacket.Packet) bool {
    anml := false
    if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
        tcpl, _ := tcp.(*layers.TCP)
        // Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
        if tcpl.FIN && tcpl.URG && tcpl.PSH {
            anml = true
        }
    }
    return anml
}

// This func get the first ip. If there are eth0 and wlan0, eth0 will be chosen.
func externalIP() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
    var ipaddr net.IP
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue // interface down
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue // loopback interface
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue // not an ipv4 address
			}
            ipaddr = ip
			return ip.String(), nil //if you want the last one, comment out this line
		}
    }
    if ipaddr == nil{
        return "", errors.New("are you connected to the network?")
    }else{
        return ipaddr.String(), nil
    }
}

func showIPAddress(led []uint32, ipaddr string) {
	ip := net.ParseIP(ipaddr)
	ipv4 := ip.To4()

    initLeds(led)
	for i := 0; i < ipv4Len; i++ {

		// number
		for j := 0; j < 8; j++ {
			t := i * 9 + j
	        if (ipv4[i]>>uint(7-j))&1 == 1 { // nth bit of Y = (X>>n)&1;
                led[t] = colors[10]
            }
	    }

		// period
		led[(i+1) * 9 - 1] = colors[1]
	}
    setLeds(led)
    err := ws2811.Render()
    if err != nil {
        ws2811.Clear()
        fmt.Println("Error during wipe " + err.Error())
        os.Exit(-1)
    }
}

func categorizePacket(packet gopacket.Packet) string {
    packetName := "Others";
    if lldp := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldp != nil {
        packetName = "LLDP"
    }else if dns := packet.Layer(layers.LayerTypeDNS); dns != nil {
        packetName = "DNS"
    }else if icmpv4 := packet.Layer(layers.LayerTypeICMPv4); icmpv4 != nil {
        packetName = "ICMP"
    }else if icmpv6 := packet.Layer(layers.LayerTypeICMPv6); icmpv6 != nil {
        packetName = "ICMP"
    }else if dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4); dhcpv4 != nil {
        packetName = "DHCP"
    }else if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
        packetName = "ARP"
    }else if igmp := packet.Layer(layers.LayerTypeIGMP); igmp != nil {
        packetName = "IGMP"
    }else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
        packetName = "UDP"
    }else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
        packetName = "TCP"
    }
    return packetName
}
