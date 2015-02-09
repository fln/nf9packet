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

	for i, _ := range packet.FlowSets {
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

func (this *DataFlowSet) dump(w io.Writer) {
	fmt.Fprint(w, "\t==== Data FlowSet ====\n")
	fmt.Fprintf(w, "\tId: %v\n", this.Id)
	fmt.Fprintf(w, "\tLength: %v\n", this.Length)
	fmt.Fprintf(w, "\tData: %v\n", this.Data)
}

func (this *TemplateFlowSet) dump(w io.Writer) {
	fmt.Fprint(w, "\t==== Template FlowSet ====\n")
	fmt.Fprintf(w, "\tId: %v\n", this.Id)
	fmt.Fprintf(w, "\tLength: %v\n", this.Length)
	for i, _ := range this.Records {
		this.Records[i].dump(w)
	}
}

func (this *OptionsTemplateFlowSet) dump(w io.Writer) {
	fmt.Fprint(w, "\t==== Options Template FlowSet ====\n")
	fmt.Fprintf(w, "\tId: %v\n", this.Id)
	fmt.Fprintf(w, "\tLength: %v\n", this.Length)
	for i, _ := range this.Records {
		this.Records[i].dump(w)
	}
}

func (this *TemplateRecord) dump(w io.Writer) {
	fmt.Fprint(w, "\t\t==== Template Record ====\n")
	fmt.Fprintf(w, "\t\tTemplateId: %v\n", this.TemplateId)
	fmt.Fprintf(w, "\t\tFieldCount: %v\n", this.FieldCount)
	for i, _ := range this.Fields {
		fmt.Fprintf(w, "\t\tType(%v), Len(%v)\n", this.Fields[i].Type, this.Fields[i].Length)
	}
}

func (this *OptionsTemplateRecord) dump(w io.Writer) {
	fmt.Fprint(w, "\t\t==== Options Template Record ====\n")
	fmt.Fprintf(w, "\t\tTemplateId: %v\n", this.TemplateId)
	fmt.Fprintf(w, "\t\tScopeLength: %v\n", this.ScopeLength)
	fmt.Fprintf(w, "\t\tOptionLength: %v\n", this.OptionLength)
	for i, _ := range this.Scopes {
		fmt.Fprintf(w, "\t\tScopeType(%v), Len(%v)\n", this.Scopes[i].Type, this.Scopes[i].Length)
	}
	for i, _ := range this.Options {
		fmt.Fprintf(w, "\t\tOptionType(%v), Len(%v)\n", this.Options[i].Type, this.Options[i].Length)
	}
}
