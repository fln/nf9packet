// Package nf9packet provides structures and functions to decode and analyze
// NetFlow v9 packets.
//
// This package does only packet decoding in a single packet context. It keeps
// no state when decoding multiple packets. As a result Data FlowSets can not be
// decoded during initial packet decoding. To decode Data FlowSets user must
// keep track of Template Records and Options Template Records manually.
//
// Examples of NetFlow v9 packets:
//
//   +--------+--------------------------------------------------------+
//   |        | +----------+ +---------+     +-----------+ +---------+ |
//   | Packet | | Template | | Data    |     | Options   | | Data    | |
//   | Header | | FlowSet  | | FlowSet | ... | Template  | | FlowSet | |
//   |        | |          | |         |     | FlowSet   | |         | |
//   |        | +----------+ +---------+     +-----------+ +---------+ |
//   +--------+--------------------------------------------------------+
//
//   +--------+----------------------------------------------+
//   |        | +---------+     +---------+      +---------+ |
//   | Packet | | Data    | ... | Data    | ...  | Data    | |
//   | Header | | FlowSet | ... | FlowSet | ...  | FlowSet | |
//   |        | +---------+     +---------+      +---------+ |
//   +--------+----------------------------------------------+
//
//   +--------+-------------------------------------------------+
//   |        | +----------+     +----------+      +----------+ |
//   | Packet | | Template |     | Template |      | Options  | |
//   | Header | | FlowSet  | ... | FlowSet  | ...  | Template | |
//   |        | |          |     |          |      | FlowSet  | |
//   |        | +----------+     +----------+      +----------+ |
//   +--------+-------------------------------------------------+
//
// Example of struct hierarchy after packet decoding:
//  Package
//  |
//  +--TemplateFlowSet
//  |  |
//  |  +--TemplateRecord
//  |  |  |
//  |  |  +--Field
//  |  |  +--...
//  |  |  +--Field
//  |  |
//  |  +--...
//  |  |
//  |  +--TemplateRecord
//  |     |
//  |     +--Field
//  |     +--...
//  |     +--Field
//  |
//  +--DataFlowSet
//  |
//  +--...
//  |
//  +--OptionsTemplateFlowSet
//  |  |
//  |  +--OptionsTemplateRecord
//  |  |  |
//  |  |  +--Field (scope)
//  |  |  +--...   (scope)
//  |  |  +--Field (scope)
//  |  |  |
//  |  |  +--Field (option)
//  |  |  +--...   (option)
//  |  |  +--Field (option)
//  |  |
//  |  +--...
//  |  |
//  |  +--OptionsTemplateRecord
//  |     |
//  |     +--Field (scope)
//  |     +--...   (scope)
//  |     +--Field (scope)
//  |     |
//  |     +--Field (option)
//  |     +--...   (option)
//  |     +--Field (option)
//  |
//  +--DataFlowSet
//
// When matched with appropriate template Data FlowSet can be decoded to list of
// Flow Data Records or list of Options Data Records. Struct hierarchy example:
//
//  []FlowDataRecord
//    |
//    +--FlowDataRecord
//    |  |
//    |  +--[]byte
//    |  +--...
//    |  +--[]byte
//    |
//    +--...
//    |
//    +--FlowDataRecord
//       |
//       +--[]byte
//       +--...
//       +--[]byte
//
//  []OptionsDataRecord
//    |
//    +--OptionsDataRecord
//    |  |
//    |  +--[]byte (scope)
//    |  +--...    (scope)
//    |  +--[]byte (scope)
//    |  |
//    |  +--[]byte (option)
//    |  +--...    (option)
//    |  +--[]byte (option)
//    |
//    +--...
//    |
//    +--OptionsDataRecord
//       |
//       +--[]byte
//       +--...
//       +--[]byte
//       |
//       +--[]byte (option)
//       +--...    (option)
//       +--[]byte (option)
//
// Most of structure names and comments are taken directly from RFC 3954.
// Reading the NetFlow v9 protocol specification is highly recommended before
// using this package.
package nf9packet

// Packet is a decoded representation of a single NetFlow v9 UDP packet.
type Packet struct {
	// Version of Flow Record format exported in this packet. The value of
	//this field is 9 for the current version.
	Version uint16

	// The total number of records in the Export Packet, which is the sum
	// of Options FlowSet records, Template FlowSet records, and Data
	// FlowSet records.
	Count uint16

	// Time in milliseconds since this device was first booted.
	SysUpTime uint32

	// Time in seconds since 0000 UTC 1970, at which the Export Packet
	// leaves the Exporter.
	UnixSecs uint32

	// Incremental sequence counter of all Export Packets sent from the
	// current Observation Domain by the Exporter.
	SequenceNumber uint32

	// A 32-bit value that identifies the Exporter Observation Domain.
	SourceId uint32

	// A slice of structs. Each element is instance of DataFlowSet or
	// TemplateFlowSet or OptionsTemplateFlowSet.
	FlowSets []interface{}
}

// DataFlowSet is a collection of Data Records (actual NetFlow data) and Options
// Data Rcords (meta data).
type DataFlowSet struct {
	FlowSetHeader

	// Raw data bytes
	Data []byte
}

// TemplateFlowSet is a collection of templates that describe structure of Data
// Records (actual NetFlow data).
type TemplateFlowSet struct {
	FlowSetHeader

	// List of Template Records
	Records []TemplateRecord
}

// OptionsTemplateFlowSet is a collection of templates that describe structure
// of Options Data Records.
type OptionsTemplateFlowSet struct {
	FlowSetHeader

	// List of Options Template Records
	Records []OptionsTemplateRecord
}

// FlowSetHeader contains fields shared by all Flow Sets (DataFlowSet,
// TemplateFlowSet, OptionsTemplateFlowSet).
type FlowSetHeader struct {
	// FlowSet ID:
	//    0 for TemplateFlowSet
	//    1 for OptionsTemplateFlowSet
	//    256-65535 for DataFlowSet (used as TemplateId)
	Id uint16

	// The total length of this FlowSet in bytes (including padding).
	Length uint16
}

// DataFlowSets generate a list of all Data FlowSets in the packet. If matched
// with appropriate templates Data FlowSets can be decoded to Data Records or
// Options Data Records.
func (p *Packet) DataFlowSets() (list []DataFlowSet) {
	for i := range p.FlowSets {
		switch set := p.FlowSets[i].(type) {
		case DataFlowSet:
			list = append(list, set)
		}
	}
	return
}

// TemplateRecords generate a list of all Template Records in the packet.
// Template Records can be used to decode Data FlowSets to Data Records.
func (p *Packet) TemplateRecords() (list []*TemplateRecord) {
	for i := range p.FlowSets {
		switch set := p.FlowSets[i].(type) {
		case TemplateFlowSet:
			for j := range set.Records {
				list = append(list, &set.Records[j])
			}
		}
	}
	return
}

// OptionsTemplateRecords generate a list of all Options Template Records in the
// packet. Options Template Records can be used to decode Data FlowSets
// to Options Data Records.
func (p *Packet) OptionsTemplateRecords() (list []*OptionsTemplateRecord) {
	for i := range p.FlowSets {
		switch set := p.FlowSets[i].(type) {
		case OptionsTemplateFlowSet:
			for j := range set.Records {
				list = append(list, &set.Records[j])
			}
		}
	}
	return
}
