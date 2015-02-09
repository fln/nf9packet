package main

import (
	"fmt"
	"os"
	"net"
	"flag"
	"encoding/json"
	"github.com/fln/nf9packet"
)

var listenAddr *string = flag.String("listen", ":9995", "Address to listen for NetFlow v9 packets.")
var dumpJson *bool = flag.Bool("json", false, "Dump packet in JSON instead of plain text.")

func packetDump(addr net.Addr, data []byte) {
	fmt.Fprintln(os.Stderr, "Got packet from: ", addr)
	p, err := nf9packet.Decode(data)

	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	if *dumpJson {
		json, _ := json.MarshalIndent(p, "", "\t")
		fmt.Printf("%s\n", json)
	} else {
		nf9packet.Dump(p, os.Stdout)
		fmt.Print("\n")
	}
}

func main() {
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	if err != nil {
		panic(err)
	}

	con, err := net.ListenUDP("udp", addr)
	if err != nil {
		panic(err)
	}

	data := make([]byte, 8960)
	for {
		length, remote, err := con.ReadFrom(data)
		if err != nil {
			panic(err)
		}

		packetDump(remote, data[:length])
	}
}
