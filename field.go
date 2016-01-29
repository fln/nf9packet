package nf9packet

// Field describes type and length of a single value in a Flow Data Record.
// Field does not contain the record value itself it is just a description of
// what record value will look like.
type Field struct {
	// A numeric value that represents the type of field.
	Type uint16

	// The length (in bytes) of the field.
	Length uint16
}

// Name returns a short field type identifier based on RFC 3954 and Cisco
// documentation. For unkown field types string "UNKNOWN_TYPE" will be returned.
func (f *Field) Name() string {
	if e, ok := fieldDb[f.Type]; ok {
		return e.Name
	}
	return "UNKNOWN_TYPE"
}

// DefaultLength returns length of field type as specified in RFC 3954 and Cisco
// documentation. For variable length fields and unknown fields -1 is returned.
func (f *Field) DefaultLength() int {
	if e, ok := fieldDb[f.Type]; ok {
		return e.Length
	}
	return -1
}

// Description returns field type description based on RFC 3954 and Cisco
// documentation. For unkown field types string "Unknown type" will be returned.
func (f *Field) Description() string {
	if e, ok := fieldDb[f.Type]; ok {
		return e.Description
	}
	return "Unknown type"
}

// DataToString converts field value to string representation based on field
// type. If used with unknow field type string "n/a" will be returned.
func (f *Field) DataToString(data []byte) string {
	if e, ok := fieldDb[f.Type]; ok {
		return e.String(data)
	}
	return "n/a"
}

// DataToUint64 converts field value to uint64. This function will not generate
// errors if used with incompatible field types. Field value length can be up to
// 8 bytes, for longer values only first 8 bytes are used.
func (f *Field) DataToUint64(data []byte) uint64 {
	return fieldToUInteger(data)
}

// ScopeName is the same as Name() but should be used only for Scope Fields
func (f *Field) ScopeName() string {
	switch f.Type {
	case 1:
		return "System"
	case 2:
		return "Interface"
	case 3:
		return "Line Card"
	case 4:
		return "Cache"
	case 5:
		return "Template"
	default:
		return "Unknown"
	}
}

// ScopeDefaultLength is the same as DefaultLength() but should be used only for Scope Fields
func (f *Field) ScopeDefaultLength() int {
	return -1
}

// ScopeDescription is the same as Description but should be used only for Scope Fields
func (f *Field) ScopeDescription() string {
	return "The relevant portion of the Exporter/NetFlow process to which the Options Template Record refers."
}
