package main

import (
	"fmt"
	"os"
	"net"
	"flag"
	"strconv"
	"github.com/fln/nf9packet"
)

type TemplateCache map[string]*nf9packet.TemplateRecord

var listenAddr *string = flag.String("listen", ":9995", "Address to listen for NetFlow v9 packets.")

func printTable(template *nf9packet.TemplateRecord, records []nf9packet.FlowDataRecord) {
	fmt.Printf("|")
	for _, f := range template.Fields {
		fmt.Printf(" %s |", f.Name())
	}
	fmt.Printf("\n")

	for _, r := range records {
		fmt.Printf("|")
		for i, _ := range r.Values {
			colWidth := len(template.Fields[i].Name())
			fmt.Printf(" %" + strconv.Itoa(colWidth) + "s |", template.Fields[i].DataToString(r.Values[i]))
		}
		fmt.Printf("\n")
	}
}

func packetDump(addr net.Addr, data []byte, cache TemplateCache) {
	p, err := nf9packet.Decode(data)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}

	templateList := p.TemplateRecords()
	flowSets := p.DataFlowSets()

	for _, t := range templateList {
		templateKey := fmt.Sprintf("%s|%b|%v", addr.String(), p.SourceId, t.TemplateId)
		cache[templateKey] = t
	}

	for _, set := range flowSets {
		templateKey := fmt.Sprintf("%s|%b|%v", addr.String(), p.SourceId, set.Id)
		template, ok := cache[templateKey]
		if !ok {
			// We do not have template for this Data FlowSet yet
			continue
		}

		records := template.DecodeFlowSet(&set)
		if records == nil {
			// Error in decoding Data FlowSet
			continue
		}
		printTable(template, records)
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
	cache := make(TemplateCache)

	for {
		length, remote, err := con.ReadFrom(data)
		if err != nil {
			panic(err)
		}

		packetDump(remote, data[:length], cache)
	}
}
