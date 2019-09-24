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
)

const (
    ipAddr     = "169.254.204.201"
    device     = "eth0"
    pin        = 18
    series     = 5
    count      = 144
    brightness = 50
    // interval   = time.Millisecond * 50
)

var (
    colors = []uint32{
        0xFFFFFF, //White
        0xFF0000, //Green
        0x00FF00, //Red
        0x0000FF, //Blue
        0x000000, //Black
        0x00FFFF, //Pink
        0xFFFF00, //Yellow
        0xFF00FF, //Light blue
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
              // src, dst := net.NetworkFlow().Endpoints()
              src, _ := net.NetworkFlow().Endpoints()
              isSrc := strings.Contains(src.String(), ipAddr)
              // isDst := strings.Contains(dst.String(), ipAddr)
              // if !((isSrc && !isDst) || (!isSrc && isDst)) {
              //     fmt.Println("src:", src, isSrc, "\tdst:", dst, isDst)
              // }
              // fmt.Println("src:", src, isSrc, "\tdst:", dst, isDst)
              if isSrc {
                  reverse = false
              }
            }

            castPacket(led, series, reverse)

            // if idx%2==0 {
            //     for i := 0; i < count; i++{
            //         wipe = initLeds()
            //         wipe[i] = colors[7]
            //
            //         colorWipe2(wipe)
            //         err := ws2811.Render()
            //         if err != nil {
            //         	ws2811.Clear()
            //         	fmt.Println("Error during wipe " + err.Error())
            //         	os.Exit(-1)
            //         }
            //     }
            // } else {
            //     for i := count-1; i >= 0 ; i--{
            //         wipe = initLeds()
            //         wipe[i] = colors[7]
            //
            //         colorWipe2(wipe)
            //         err := ws2811.Render()
            //         if err != nil {
            //             ws2811.Clear()
            //             fmt.Println("Error during wipe " + err.Error())
            //             os.Exit(-1)
            //         }
            //     }
            // }
            // idx += 1
        }
        // time.Sleep(interval)
    }
}

func color() func() uint32 {
    i := -1
    return func() uint32 {
        i++
        return colors[i%len(colors)]
    }
}

func vLeds() []uint32 {
    alength := series * len(colors)
    for {
        if alength >= count {
            break
        }
        alength += alength
    }
    return make([]uint32, alength)
}

func genLedSet() func() []uint32 {
    color := color()
    base := 0
    return func() []uint32 {
        vled := vLeds()
        for i := base; i < base+len(vled); {
            color := color()
            for j := 0; j < series; j++ {
                vled[i%len(vled)] = color
                i++
            }
        }
        base++
        return vled
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

func castPacket(led []uint32, k int, reverse bool) {
    for i := -(k-1); i < len(led)+1; i++ {
        initLeds(led)

        for j := 0; j < k; j++ {
            if t := i + j; 0 <= t && t < len(led) {
                led[t] = uint32(colors[0] * (j+1) / k)
            }
        }

        if reverse {
            reverseLeds(led)
        }

        colorWipe2(led)
        err := ws2811.Render()
        if err != nil {
            ws2811.Clear()
            fmt.Println("Error during wipe " + err.Error())
            os.Exit(-1)
        }
    }
}

func colorWipe2(wipe []uint32) {
	for i := 0; i < count; i++ {
		ws2811.SetLed(i, wipe[i])
	}
}

func colorWipe(color uint32) error {
	for i := 0; i < count; i++ {
		ws2811.SetLed(i, color)
		err := ws2811.Render()
		if err != nil {
			ws2811.Clear()
			return err
		}

		time.Sleep(50 * time.Millisecond)
	}

	return nil
}
