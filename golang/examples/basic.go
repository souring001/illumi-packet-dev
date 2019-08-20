package main

import (
    "fmt"
    "time"

    "github.com/jgarff/rpi_ws281x/golang/ws2811"
)

const (
    pin        = 18
    series     = 4
    count      = 60
    brightness = 50
    interval   = time.Millisecond * 10
)

var (
    colors = []uint32{
        0xFFFFFF, //white
        //0xFF0000, //green
        0x00FF00, //Red
        0x0000FF, //Blue
        //0x00FFFF, //pink
        //0xFFFF00, //yellow
        //0xFF00FF, //light blue
    }
)

func main() {
    defer ws2811.Fini()
    err := ws2811.Init(pin, count, brightness)
    if err != nil {
        fmt.Println(err)
    } else {
        gen := genLedSet()
        for {
            set := gen()
            for i, c := range set {
                if i == count {
                    break
                }
                ws2811.SetLed(i, c)
            }
            err := ws2811.Render()
            if err != nil {
                ws2811.Clear()
            }
            time.Sleep(interval)
        }
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
