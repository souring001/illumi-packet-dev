package main

import (
    "fmt"
    "time"
	"log"
	"os"

    "github.com/jgarff/rpi_ws281x/golang/ws2811"
	"github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

const (
    pin        = 18
    series     = 4
    count      = 60
    brightness = 50
    interval   = time.Millisecond * 50
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

	device       string = "eth0"
    snapshot_len int32  = 1024
    promiscuous  bool   = false
    err          error
    timeout      time.Duration = 250 * time.Millisecond
    handle       *pcap.Handle
	idx = 1
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

		wipe := initLeds()
		fmt.Println("Initialize color wipe")

		// Use the handle as a packet source to process all packets
	    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	    for packet := range packetSource.Packets() {
	        // Process packet here
	        fmt.Println(packet)

			if idx%2==0 {
				for i := 0; i < count; i++{
					wipe = initLeds()
					wipe[i] = colors[7]

					colorWipe2(wipe)
					err := ws2811.Render()
					if err != nil {
						ws2811.Clear()
						fmt.Println("Error during wipe " + err.Error())
						os.Exit(-1)
					}
				}
			} else {
				for i := count-1; i >= 0 ; i--{
					wipe = initLeds()
					wipe[i] = colors[7]

					colorWipe2(wipe)
					err := ws2811.Render()
					if err != nil {
						ws2811.Clear()
						fmt.Println("Error during wipe " + err.Error())
						os.Exit(-1)
					}
				}
			}

			idx += 1
	    }

		time.Sleep(interval)
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

func initLeds() []uint32 {
    return make([]uint32, count)
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
