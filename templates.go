package nf9packet

import (
	"bytes"
)

type TemplateRecord struct {
	// Each of the newly generated Template Records is given a unique
	// Template ID. This uniqueness is local to the Observation Domain that
	// generated the Template ID. Template IDs of Data FlowSets are numbered
	// from 256 to 65535.
	TemplateId uint16

	// Number of fields in this Template Record. Because a Template FlowSet
	// usually contains multiple Template Records, this field allows the
	// Collector to determine the end of the current Template Record and
	// the start of the next.
	FieldCount uint16

	// List of fields in this Template Record.
	Fields []Field
}

type OptionsTemplateRecord struct {
	// Template ID of this Options Template. This value is greater than 255.
	TemplateId uint16

	// The length in bytes of all Scope field definitions contained in this
	// Options Template Record.
	ScopeLength uint16

	// The length (in bytes) of all options field definitions contained in
	// this Options Template Record.
	OptionLength uint16

	// List of Scope fields in this Options Template Record.
	Scopes []Field

	// List of Option fields in this Options Template Record.
	Options []Field
}

type FlowDataRecord struct {
	// List of Flow Data Record values stored in raw format as []byte
	Values [][]byte
}

type OptionsDataRecord struct {
	// List of Scope values stored in raw format as []byte
	ScopeValues [][]byte

	// List of Optons values stored in raw format as []byte
	OptionValues [][]byte
}

func parseFieldValues(buf *bytes.Buffer, fields []Field) (values [][]byte) {
	values = make([][]byte, len(fields))
	for i, f := range fields {
		if buf.Len() < int(f.Length) {
			return nil
		}
		values[i] = buf.Next(int(f.Length))
	}
	return
}

// DecodeFlowSet uses current TemplateRecord to decode data in Data FlowSet to
// a list of Flow Data Records.
func (this *TemplateRecord) DecodeFlowSet(set *DataFlowSet) (list []FlowDataRecord) {
	var record FlowDataRecord
	buf := bytes.NewBuffer(set.Data)

	if (set.Id != this.TemplateId) {
		return
	}

	// Assume total record length must be >= 4, otherwise it is impossible
	// to distinguish between padding and new record. Padding MUST be
	// supported.
	for i := 0; buf.Len() >= 4; i += 1 {
		record.Values = parseFieldValues(buf, this.Fields)
		list = append(list, record)
	}

	return
}

// DecodeFlowSet uses current OptionsTemplateRecord to decode data in Data
// FlowSet to a list of Options Data Records.
func (this *OptionsTemplateRecord) DecodeFlowSet(set *DataFlowSet) (list []OptionsDataRecord) {
	var record OptionsDataRecord
	buf := bytes.NewBuffer(set.Data)

	if (set.Id != this.TemplateId) {
		return
	}

	// Assume total record length must be >= 4, otherwise it is impossible
	// to distinguish between padding and new record. Padding MUST be
	// supported.
	for i := 0; buf.Len() >= 4; i += 1 {
		record.ScopeValues = parseFieldValues(buf, this.Scopes)
		record.OptionValues = parseFieldValues(buf, this.Options)
		list = append(list, record)
	}
	return
}
