package nf9packet

import (
	"fmt"
	"io"
)

// Dump prints decoded packet structure, listing all structure fields and values
// in a simple plain text format format. It is used for debugging and simple
// packet inspection. Argument w can be os.Stdout or any other Writer
// implementation.
func Dump(packet *Packet, w io.Writer) {
	fmt.Fprint(w, "==== Netflow v9 Packet ====\n")
	fmt.Fprintf(w, "Version: %v\n", packet.Version)
	fmt.Fprintf(w, "Count: %v\n", packet.Count)
	fmt.Fprintf(w, "SysUpTime: %v\n", packet.SysUpTime)
	fmt.Fprintf(w, "UnixSecs: %v\n", packet.UnixSecs)
	fmt.Fprintf(w, "SequenceNumber: %v\n", packet.SequenceNumber)
	fmt.Fprintf(w, "SourceId: %v\n", packet.SourceId)

	for i := range packet.FlowSets {
		switch set := packet.FlowSets[i].(type) {
		case DataFlowSet:
			set.dump(w)
		case TemplateFlowSet:
			set.dump(w)
		case OptionsTemplateFlowSet:
			set.dump(w)
		}
	}
}

func (dfs *DataFlowSet) dump(w io.Writer) {
	fmt.Fprint(w, "\t==== Data FlowSet ====\n")
	fmt.Fprintf(w, "\tId: %v\n", dfs.Id)
	fmt.Fprintf(w, "\tLength: %v\n", dfs.Length)
	fmt.Fprintf(w, "\tData: %v\n", dfs.Data)
}

func (dtpls *TemplateFlowSet) dump(w io.Writer) {
	fmt.Fprint(w, "\t==== Template FlowSet ====\n")
	fmt.Fprintf(w, "\tId: %v\n", dtpls.Id)
	fmt.Fprintf(w, "\tLength: %v\n", dtpls.Length)
	for i := range dtpls.Records {
		dtpls.Records[i].dump(w)
	}
}

func (otpls *OptionsTemplateFlowSet) dump(w io.Writer) {
	fmt.Fprint(w, "\t==== Options Template FlowSet ====\n")
	fmt.Fprintf(w, "\tId: %v\n", otpls.Id)
	fmt.Fprintf(w, "\tLength: %v\n", otpls.Length)
	for i := range otpls.Records {
		otpls.Records[i].dump(w)
	}
}

func (dtpl *TemplateRecord) dump(w io.Writer) {
	fmt.Fprint(w, "\t\t==== Template Record ====\n")
	fmt.Fprintf(w, "\t\tTemplateId: %v\n", dtpl.TemplateId)
	fmt.Fprintf(w, "\t\tFieldCount: %v\n", dtpl.FieldCount)
	for i := range dtpl.Fields {
		fmt.Fprintf(w, "\t\tType(%v), Len(%v)\n", dtpl.Fields[i].Type, dtpl.Fields[i].Length)
	}
}

func (otpl *OptionsTemplateRecord) dump(w io.Writer) {
	fmt.Fprint(w, "\t\t==== Options Template Record ====\n")
	fmt.Fprintf(w, "\t\tTemplateId: %v\n", otpl.TemplateId)
	fmt.Fprintf(w, "\t\tScopeLength: %v\n", otpl.ScopeLength)
	fmt.Fprintf(w, "\t\tOptionLength: %v\n", otpl.OptionLength)
	for i := range otpl.Scopes {
		fmt.Fprintf(w, "\t\tScopeType(%v), Len(%v)\n", otpl.Scopes[i].Type, otpl.Scopes[i].Length)
	}
	for i := range otpl.Options {
		fmt.Fprintf(w, "\t\tOptionType(%v), Len(%v)\n", otpl.Options[i].Type, otpl.Options[i].Length)
	}
}
