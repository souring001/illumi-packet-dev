package main

import (
    "fmt"
    "strings"
    "time"
    "log"
    "os"

    "github.com/jgarff/rpi_ws281x/golang/ws2811"
    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/layers"
)

const (
    ipAddr     = "169.254.204.201"
    device     = "eth0"
    pin        = 18
    series     = 12
    speed      = 4
    count      = 144
    brightness = 50 // default 255
)

var (
    colors = []uint32{
        0xFFFFFF, //0 White others
        0x880000, //1 Green UDP
        0x00FF00, //2 Red
        0x0000FF, //3 Blue UDP
        0x000000, //4 Purple ARP
        0x00FFFF, //5 Pink ICMP
        0xFFFF00, //6 Yellow
        0x88FF00, //7 Orange IGMP
        0xFF00FF, //8 Cyan DHCP
        0xFF0000, //9 Lime DNS
    }

    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 50 * time.Millisecond
    handle       *pcap.Handle
)

func main() {
    // Open device
    handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
    if err != nil {log.Fatal(err) }
    defer handle.Close()

    defer ws2811.Fini()
    err := ws2811.Init(pin, count, brightness)
    if err != nil {
        fmt.Println(err)
    } else {
        fmt.Println("Press Ctr-C to quit.")

        led := make([]uint32, count)
        fmt.Println("Initialize color leds")

        // Use the handle as a packet source to process all packets
        packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
        fmt.Println("start capturing...")

        for packet := range packetSource.Packets() {
            // Process packet here

            reverse := true
            if net := packet.NetworkLayer(); net != nil {
                src, dst := net.NetworkFlow().Endpoints()
                isSrc := strings.Contains(src.String(), ipAddr)
                // isDst := strings.Contains(dst.String(), ipAddr)
                // if !((isSrc && !isDst) || (!isSrc && isDst)) {
                //     fmt.Println("src:", src, isSrc, "\tdst:", dst, isDst)
                // }
                fmt.Printf("src:", src)
                if isSrc {
                    reverse = false
                }
                if reverse {
                    fmt.Println("\t<-")
                } else {
                    fmt.Println("\t->")
                }
                fmt.Printf("\tdst:", dst)
            }
            // fmt.Println(packet)
            if lldp := packet.Layer(layers.LayerTypeLinkLayerDiscovery); lldp != nil {
                fmt.Println("LLDP")
                castPacket(led, series, colors[0], reverse)
                fmt.Println(packet)
            }else if dns := packet.Layer(layers.LayerTypeDNS); dns != nil {
                fmt.Println("DNS")
                castPacket(led, series, colors[9], reverse)
                fmt.Println(packet)
            }else if icmpv4 := packet.Layer(layers.LayerTypeICMPv4); icmpv4 != nil {
                fmt.Println("ICMPv4")
                castPacket(led, series, colors[5], reverse)
                fmt.Println(packet)
            }else if icmpv6 := packet.Layer(layers.LayerTypeICMPv6); icmpv6 != nil {
                fmt.Println("ICMPv6")
                castPacket(led, series, colors[5], reverse)
                fmt.Println(packet)
            }else if dhcpv4 := packet.Layer(layers.LayerTypeDHCPv4); dhcpv4 != nil {
                fmt.Println("DHCPv4")
                castPacket(led, series, colors[8], reverse)
                fmt.Println(packet)
            }else if arp := packet.Layer(layers.LayerTypeARP); arp != nil {
                fmt.Println("ARP")
                castPacket(led, series, colors[4], reverse)
                fmt.Println(packet)
            }else if igmp := packet.Layer(layers.LayerTypeIGMP); igmp != nil {
                fmt.Println("IGMP")
                castPacket(led, series, colors[7], reverse)
                fmt.Println(packet)
            }else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
                fmt.Println("UDP")
                castPacket(led, series, colors[1], reverse)
                fmt.Println(packet)
            }else if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
                // fmt.Println("TCP")
                // castPacket(led, series, colors[0], reverse)
                // fmt.Println(packet)
            }else{
                fmt.Println("OTHERS")
                castPacket(led, series, colors[0], reverse)
                fmt.Println(packet)
            }
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
    for i := -(k-1); i < len(led)+series; i += speed {
        initLeds(led)

        for j := 0; j < k; j++ {
            if t := i + j; 0 <= t && t < len(led) {
                // packet gradiation
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
