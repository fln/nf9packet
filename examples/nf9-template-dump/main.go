package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	"github.com/fln/nf9packet"
)

func packetDump(addr net.Addr, data []byte) {
	p, err := nf9packet.Decode(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	templateList := p.TemplateRecords()
	optTemplateList := p.OptionsTemplateRecords()

	for _, t := range templateList {
		fmt.Printf("==== %v, SourceId: %v, TemplateId: %v ====\n", addr, p.SourceId, t.TemplateId)
		fmt.Print("--- Field name (actual length / default length) description ---\n")
		for _, f := range t.Fields {
			fmt.Printf("%-24s (%2v / %2v) %s\n", f.Name(), f.Length, f.DefaultLength(), f.Description())
		}
		fmt.Print("\n")
	}

	for _, t := range optTemplateList {
		fmt.Printf("==== %v, SourceId: %v, OptionsTemplateId: %v ====\n", addr, p.SourceId, t.TemplateId)
		fmt.Print("--- Scopes ---\n")
		for _, f := range t.Scopes {
			fmt.Printf("%-24s (%2v / %2v) %s\n", f.ScopeName(), f.Length, f.ScopeDefaultLength(), f.ScopeDescription())
		}
		fmt.Print("--- Options ---\n")
		for _, f := range t.Options {
			fmt.Printf("%-24s (%2v / %2v) %s\n", f.Name(), f.Length, f.DefaultLength(), f.Description())
		}
		fmt.Print("\n")
	}
}

func main() {
	listenAddr := flag.String("listen", ":9995", "Address to listen for NetFlow v9 packets.")
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
