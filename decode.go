package nf9packet

import (
	"fmt"
	"bytes"
	"encoding/binary"
)

func errorMissingData(bytes int) error {
	return fmt.Errorf("Incomplete packet, missing at least %d bytes.", bytes)
}

func errorIncompatibleVersion(version uint16) error {
	return fmt.Errorf("Incompatible protocol version v%d, only v9 is supported", version)
}

func errorExtraBytes(bytes int) error {
	return fmt.Errorf("Extra %d bytes at the end of the packet.", bytes)
}


func parseFieldList(buf *bytes.Buffer, count int) (list []Field) {
	list = make([]Field, count)

	for i := 0; i < count; i += 1 {
		binary.Read(buf, binary.BigEndian, &list[i])
	}

	return
}

func parseOptionsTemplateFlowSet(data []byte, header *FlowSetHeader) (interface{}, error) {
	var set OptionsTemplateFlowSet
	var t OptionsTemplateRecord

	set.Id = header.Id
	set.Length = header.Length

	buf := bytes.NewBuffer(data)
	headerLen := binary.Size(t.TemplateId) + binary.Size(t.ScopeLength) + binary.Size(t.OptionLength)
	for ; buf.Len() >= 4 ; { // Padding aligns to 4 byte boundary
		if buf.Len() < headerLen {
			return nil, errorMissingData(headerLen - buf.Len())
		}
		binary.Read(buf, binary.BigEndian, &t.TemplateId)
		binary.Read(buf, binary.BigEndian, &t.ScopeLength)
		binary.Read(buf, binary.BigEndian, &t.OptionLength)

		if buf.Len() < int(t.ScopeLength) + int(t.OptionLength) {
			return nil, errorMissingData(int(t.ScopeLength) + int(t.OptionLength) - buf.Len())
		}

		scopeCount := int(t.ScopeLength) / binary.Size(Field{})
		optionCount := int(t.OptionLength) / binary.Size(Field{})

		t.Scopes = parseFieldList(buf, scopeCount)
		t.Options = parseFieldList(buf, optionCount)

		set.Records = append(set.Records, t)
	}

	return set, nil
}


func parseTemplateFlowSet(data []byte, header *FlowSetHeader) (interface{}, error) {
	var set TemplateFlowSet
	var t TemplateRecord

	set.Id = header.Id
	set.Length = header.Length

	buf := bytes.NewBuffer(data)
	headerLen := binary.Size(t.TemplateId) + binary.Size(t.FieldCount)

	for ; buf.Len() >= 4 ; { // Padding aligns to 4 byte boundary
		if buf.Len() < headerLen {
			return nil, errorMissingData(headerLen - buf.Len())
		}
		binary.Read(buf, binary.BigEndian, &t.TemplateId)
		binary.Read(buf, binary.BigEndian, &t.FieldCount)

		fieldsLen := int(t.FieldCount) * binary.Size(Field{})
		if fieldsLen > buf.Len() {
			return nil, errorMissingData(fieldsLen - buf.Len())
		}
		t.Fields = parseFieldList(buf, int(t.FieldCount))

		set.Records = append(set.Records, t)
	}
	return set, nil

}

func parseDataFlowSet(data []byte, header *FlowSetHeader) (interface{}, error) {
	var set DataFlowSet

	set.Id = header.Id
	set.Length = header.Length
	set.Data = data

	return set, nil
}

func parseFlowSet(buf *bytes.Buffer) (interface {}, error) {
	var setHeader FlowSetHeader

	if buf.Len() < binary.Size(setHeader) {
		return nil, errorMissingData(binary.Size(setHeader) - buf.Len())
	}

	binary.Read(buf, binary.BigEndian, &setHeader)

	setDataLen := int(setHeader.Length) - binary.Size(setHeader)
	if setDataLen > buf.Len() {
		return nil, errorMissingData(setDataLen - buf.Len())
	}

	switch {
	case setHeader.Id == 0:
		return  parseTemplateFlowSet(buf.Next(setDataLen), &setHeader)
	case setHeader.Id == 1:
		return parseOptionsTemplateFlowSet(buf.Next(setDataLen), &setHeader)
	default:
		return parseDataFlowSet(buf.Next(setDataLen), &setHeader)
	}
}

// Decode is the main function of this package. It converts raw packet bytes to
// Packet struct.
func Decode(data []byte) (*Packet, error) {
	var p Packet
	var err error
	buf := bytes.NewBuffer(data)

	headerLen := binary.Size(p.Version) + binary.Size(p.Count) +
			binary.Size(p.SysUpTime) + binary.Size(p.UnixSecs) +
			binary.Size(p.SequenceNumber) + binary.Size(p.SourceId)

	if buf.Len() < headerLen {
		return nil, errorMissingData(headerLen - buf.Len())
	}

	binary.Read(buf, binary.BigEndian, &p.Version)
	binary.Read(buf, binary.BigEndian, &p.Count)
	binary.Read(buf, binary.BigEndian, &p.SysUpTime)
	binary.Read(buf, binary.BigEndian, &p.UnixSecs)
	binary.Read(buf, binary.BigEndian, &p.SequenceNumber)
	binary.Read(buf, binary.BigEndian, &p.SourceId)

	if p.Version != 9 {
		return nil, errorIncompatibleVersion(p.Version)
	}

	p.FlowSets = make([]interface{}, 0, p.Count)

	for i := 0; buf.Len() > 0 && i < int(p.Count); i +=1 {
		p.FlowSets = p.FlowSets[0 : i+1]
		p.FlowSets[i], err = parseFlowSet(buf)
		if err != nil {
			return nil, err
		}
	}

	if buf.Len() > 0 {
		return nil, errorExtraBytes(buf.Len())
	}

	return &p, nil
}
