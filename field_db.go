package nf9packet

import (
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"time"
)

type fieldDbEntry struct {
	Name        string
	Length      int
	String      func(bytes []uint8) string
	Description string
}

var fieldDb = map[uint16]fieldDbEntry{
	1:  fieldDbEntry{"IN_BYTES", -1, fieldToStringUInteger, "Incoming counter with length N x 8 bits for the number of bytes associated with an IP Flow. By default N is 4."},
	2:  fieldDbEntry{"IN_PKTS", -1, fieldToStringUInteger, "Incoming counter with length N x 8 bits for the number of packes associated with an IP Flow. By default N is 4."},
	3:  fieldDbEntry{"FLOWS", -1, fieldToStringUInteger, "Number of Flows that were aggregated; by default N is 4."},
	4:  fieldDbEntry{"PROTOCOL", 1, fieldToStringHex, "IP protocol byte."},
	5:  fieldDbEntry{"SRC_TOS", 1, fieldToStringHex, "Type of service byte setting when entering the incoming interface."},
	6:  fieldDbEntry{"TCP_FLAGS", 1, fieldToStringTCPFlags, "TCP flags; cumulative of all the TCP flags seen in this Flow."},
	7:  fieldDbEntry{"L4_SRC_PORT", 2, fieldToStringUInteger, "TCP/UDP source port number (for example, FTP, Telnet, or equivalent)."},
	8:  fieldDbEntry{"IPV4_SRC_ADDR", 4, fieldToStringIP, "IPv4 source address."},
	9:  fieldDbEntry{"SRC_MASK", 1, fieldToStringUInteger, "The number of contiguous bits in the source subnet mask (i.e., the mask in slash notation)."},
	10: fieldDbEntry{"INPUT_SNMP", -1, fieldToStringUInteger, "Input interface index. By default N is 2, but higher values can be used."},
	11: fieldDbEntry{"L4_DST_PORT", 2, fieldToStringUInteger, "TCP/UDP destination port number (for example, FTP, Telnet, or equivalent)."},
	12: fieldDbEntry{"IPV4_DST_ADDR", 4, fieldToStringIP, "IPv4 destination address."},
	13: fieldDbEntry{"DST_MASK", 1, fieldToStringUInteger, "The number of contiguous bits in the destination subnet mask (i.e., the mask in slash notation)."},
	14: fieldDbEntry{"OUTPUT_SNMP", -1, fieldToStringUInteger, "Output interface index. By default N is 2, but higher values can be used."},
	15: fieldDbEntry{"IPV4_NEXT_HOP", 4, fieldToStringIP, "IPv4 address of the next-hop router."},
	16: fieldDbEntry{"SRC_AS", -1, fieldToStringUInteger, "Source BGP autonomous system number where N could be 2 or 4. By default N is 2."},
	17: fieldDbEntry{"DST_AS", -1, fieldToStringUInteger, "Destination BGP autonomous system number where N could be 2 or 4. By default N is 2."},
	18: fieldDbEntry{"BGP_IPV4_NEXT_HOP", 4, fieldToStringIP, "Next-hop router's IP address in the BGP domain."},
	19: fieldDbEntry{"MUL_DST_PKTS", -1, fieldToStringUInteger, "IP multicast outgoing packet counter with length N x 8 bits for packets associated with the IP Flow. By default N is 4."},
	20: fieldDbEntry{"MUL_DST_BYTES", -1, fieldToStringUInteger, "IP multicast outgoing Octet (byte) counter with length N x 8 bits for the number of bytes associated with the IP Flow. By default N is 4."},
	21: fieldDbEntry{"LAST_SWITCHED", 4, fieldToStringMsecDuration, "sysUptime in msec at which the last packet of this Flow was switched."},
	22: fieldDbEntry{"FIRST_SWITCHED", 4, fieldToStringMsecDuration, "sysUptime in msec at which the first packet of this Flow was switched."},
	23: fieldDbEntry{"OUT_BYTES", -1, fieldToStringUInteger, "Outgoing counter with length N x 8 bits for the number of bytes associated with an IP Flow. By default N is 4."},
	24: fieldDbEntry{"OUT_PKTS", -1, fieldToStringUInteger, "Outgoing counter with length N x 8 bits for the number of packets associated with an IP Flow. By default N is 4."},
	25: fieldDbEntry{"MIN_PKT_LNGTH", 2, fieldToStringUInteger, "Minimum IP packet length on incoming packets of the flow."},
	26: fieldDbEntry{"MAX_PKT_LNGTH", 2, fieldToStringUInteger, "Maximum IP packet length on incoming packets of the flow."},
	27: fieldDbEntry{"IPV6_SRC_ADDR", 16, fieldToStringIP, "IPv6 source address."},
	28: fieldDbEntry{"IPV6_DST_ADDR", 16, fieldToStringIP, "IPv6 destination address."},
	29: fieldDbEntry{"IPV6_SRC_MASK", 1, fieldToStringUInteger, "Length of the IPv6 source mask in contiguous bits."},
	30: fieldDbEntry{"IPV6_DST_MASK", 1, fieldToStringUInteger, "Length of the IPv6 destination mask in contiguous bits."},
	31: fieldDbEntry{"IPV6_FLOW_LABEL", 3, fieldToStringHex, "IPv6 flow label as per RFC 2460 definition."},
	32: fieldDbEntry{"ICMP_TYPE", 2, fieldToStringICMPTypeCode, "Internet Control Message Protocol (ICMP) packet type; reported as ICMP Type * 256 + ICMP code."},
	33: fieldDbEntry{"MUL_IGMP_TYPE", 1, fieldToStringUInteger, "Internet Group Management Protocol (IGMP) packet type."},
	34: fieldDbEntry{"SAMPLING_INTERVAL", 4, fieldToStringSamplingInterval, "When using sampled NetFlow, the rate at which packets are sampled; for example, a value of 100 indicates that one of every hundred packets is sampled."},
	35: fieldDbEntry{"SAMPLING_ALGORITHM", 1, fieldToStringSamplingAlgo, "For sampled NetFlow platform-wide: 0x01 deterministic sampling, 0x02 random sampling. Use in connection with SAMPLING_INTERVAL."},
	36: fieldDbEntry{"FLOW_ACTIVE_TIMEOUT", 2, fieldToStringUInteger, "Timeout value (in seconds) for active flow entries in the NetFlow cache."},
	37: fieldDbEntry{"FLOW_INACTIVE_TIMEOUT", 2, fieldToStringUInteger, "Timeout value (in seconds) for inactive Flow entries in the NetFlow cache."},
	38: fieldDbEntry{"ENGINE_TYPE", 1, fieldToStringEngineType, "Type of Flow switching engine (route processor, linecard, etc...)."},
	39: fieldDbEntry{"ENGINE_ID", 1, fieldToStringUInteger, "ID number of the Flow switching engine."},
	40: fieldDbEntry{"TOTAL_BYTES_EXP", -1, fieldToStringUInteger, "Counter with length N x 8 bits for the number of bytes exported by the Observation Domain. By default N is 4."},
	41: fieldDbEntry{"TOTAL_PKTS_EXP", -1, fieldToStringUInteger, "Counter with length N x 8 bits for the number of packets exported by the Observation Domain. By default N is 4."},
	42: fieldDbEntry{"TOTAL_FLOWS_EXP", -1, fieldToStringUInteger, "Counter with length N x 8 bits for the number of Flows exported by the Observation Domain. By default N is 4."},
	43: fieldDbEntry{"VENDOR_PROPRIETARY_43", -1, fieldToStringHex, "*Vendor Proprietary*"},
	44: fieldDbEntry{"IPV4_SRC_PREFIX", 4, fieldToStringIP, "IPv4 source address prefix (specific for Catalyst architecture)."},
	45: fieldDbEntry{"IPV4_DST_PREFIX", 4, fieldToStringIP, "IPv4 destination address prefix (specific for Catalyst architecture)."},
	46: fieldDbEntry{"MPLS_TOP_LABEL_TYPE", 1, fieldToStringMPLSTopLabelType, "MPLS Top Label Type: 0x00 UNKNOWN, 0x01 TE-MIDPT, 0x02 ATOM, 0x03 VPN, 0x04 BGP, 0x05 LDP."},
	47: fieldDbEntry{"MPLS_TOP_LABEL_IP_ADDR", 4, fieldToStringIP, "Forwarding Equivalent Class corresponding to the MPLS Top Label."},
	48: fieldDbEntry{"FLOW_SAMPLER_ID", -1, fieldToStringUInteger, "Identifier shown in \"show flow-sampler\". By default N is 4."},
	49: fieldDbEntry{"FLOW_SAMPLER_MODE", 1, fieldToStringSamplingAlgo, "The type of algorithm used for sampling data: 0x02 random sampling. Use in connection with FLOW_SAMPLER_MODE."},
	50: fieldDbEntry{"FLOW_SAMPLER_RANDOM_INTERVAL", 4, fieldToStringUInteger, "Packet interval at which to sample. Use in connection with FLOW_SAMPLER_MODE."},
	51: fieldDbEntry{"VENDOR_PROPRIETARY_50", -1, fieldToStringHex, "*Vendor Proprietary*"},
	52: fieldDbEntry{"MIN_TTL", 1, fieldToStringUInteger, "Minimum TTL on incoming packets of the flow."},
	53: fieldDbEntry{"MAX_TTL", 1, fieldToStringUInteger, "Maximum TTL on incoming packets of the flow."},
	54: fieldDbEntry{"IPV4_IDENT", 2, fieldToStringHex, "The IP v4 identification field."},
	55: fieldDbEntry{"DST_TOS", 1, fieldToStringHex, "Type of Service byte setting when exiting outgoing interface."},
	56: fieldDbEntry{"IN_SRC_MAC", 6, fieldToStringMAC, "Source MAC Address."},
	57: fieldDbEntry{"OUT_DST_MAC", 6, fieldToStringMAC, "Destination MAC Address."},
	58: fieldDbEntry{"SRC_VLAN", 2, fieldToStringUInteger, "Virtual LAN identifier associated with ingress interface."},
	59: fieldDbEntry{"DST_VLAN", 2, fieldToStringUInteger, "Virtual LAN identifier associated with egress interface."},
	60: fieldDbEntry{"IP_PROTOCOL_VERSION", 1, fieldToStringUInteger, "Internet Protocol Version. Set to 4 for IPv4, set to 6 for IPv6. If not present in the template, then version 4 is assumed."},
	61: fieldDbEntry{"DIRECTION", 1, fieldToStringDirection, "Flow direction: 0 - ingress flow, 1 - egress flow."},
	62: fieldDbEntry{"IPV6_NEXT_HOP", 16, fieldToStringIP, "IPv6 address of the next-hop router."},
	63: fieldDbEntry{"BGP_IPV6_NEXT_HOP", 16, fieldToStringIP, "Next-hop router in the BGP domain."},
	64: fieldDbEntry{"IPV6_OPTIONS_HEADERS", 4, fieldToStringHex, "Bit-encoded field identifying IPv6 option headers found in the flow."},
	65: fieldDbEntry{"VENDOR_PROPRIETARY_65", -1, fieldToStringHex, "*Vendor Proprietary*"},
	66: fieldDbEntry{"VENDOR_PROPRIETARY_66", -1, fieldToStringHex, "*Vendor Proprietary*"},
	67: fieldDbEntry{"VENDOR_PROPRIETARY_67", -1, fieldToStringHex, "*Vendor Proprietary*"},
	68: fieldDbEntry{"VENDOR_PROPRIETARY_68", -1, fieldToStringHex, "*Vendor Proprietary*"},
	69: fieldDbEntry{"VENDOR_PROPRIETARY_69", -1, fieldToStringHex, "*Vendor Proprietary*"},
	70: fieldDbEntry{"MPLS_LABEL_1", 3, fieldToStringMPLSLabel, "MPLS label at position 1 in the stack."},
	71: fieldDbEntry{"MPLS_LABEL_2", 3, fieldToStringMPLSLabel, "MPLS label at position 2 in the stack."},
	72: fieldDbEntry{"MPLS_LABEL_3", 3, fieldToStringMPLSLabel, "MPLS label at position 3 in the stack."},
	73: fieldDbEntry{"MPLS_LABEL_4", 3, fieldToStringMPLSLabel, "MPLS label at position 4 in the stack."},
	74: fieldDbEntry{"MPLS_LABEL_5", 3, fieldToStringMPLSLabel, "MPLS label at position 5 in the stack."},
	75: fieldDbEntry{"MPLS_LABEL_6", 3, fieldToStringMPLSLabel, "MPLS label at position 6 in the stack."},
	76: fieldDbEntry{"MPLS_LABEL_7", 3, fieldToStringMPLSLabel, "MPLS label at position 7 in the stack."},
	77: fieldDbEntry{"MPLS_LABEL_8", 3, fieldToStringMPLSLabel, "MPLS label at position 8 in the stack."},
	78: fieldDbEntry{"MPLS_LABEL_9", 3, fieldToStringMPLSLabel, "MPLS label at position 9 in the stack."},
	79: fieldDbEntry{"MPLS_LABEL_10", 3, fieldToStringMPLSLabel, "MPLS label at position 10 in the stack."},
	80: fieldDbEntry{"IN_DST_MAC", 6, fieldToStringMAC, "Incoming destination MAC address."},
	81: fieldDbEntry{"OUT_SRC_MAC", 6, fieldToStringMAC, "Outgoing source MAC address."},
	82: fieldDbEntry{"IF_NAME", -1, fieldToStringASCII, "Shortened interface name i.e.: \"FE1/0\"."},
	83: fieldDbEntry{"IF_DESC", -1, fieldToStringASCII, "Full interface name i.e.: \"FastEthernet 1/0\"."},
	84: fieldDbEntry{"SAMPLER_NAME", -1, fieldToStringASCII, "Name of the flow sampler."},
	85: fieldDbEntry{"IN_PERMANENT_BYTES", -1, fieldToStringUInteger, "Running byte counter for a permanent flow. By default N is 4."},
	86: fieldDbEntry{"IN_PERMANENT_PKTS", -1, fieldToStringUInteger, "Running packet counter for a permanent flow. By default N is 4."},
	87: fieldDbEntry{"VENDOR_PROPRIETARY_87", -1, fieldToStringHex, "*Vendor Proprietary*"},
	88: fieldDbEntry{"FRAGMENT_OFFSET", 2, fieldToStringUInteger, "The fragment-offset value from fragmented IP packets."},
	89: fieldDbEntry{"FORWARDING_STATUS", 1, fieldToStringHex, "Forwarding status is encoded on 1 byte with the 2 left bits giving the status and the 6 remaining bits giving the reason code."},
	90: fieldDbEntry{"MPLS_PAL_RD", 8, fieldToStringHex, "MPLS PAL Route Distinguisher."},
	91: fieldDbEntry{"MPLS_PREFIX_LEN", 1, fieldToStringUInteger, "Number of consecutive bits in the MPLS prefix length."},
	92: fieldDbEntry{"SRC_TRAFFIC_INDEX", 4, fieldToStringUInteger, "BGP Policy Accounting Source Traffic Index."},
	93: fieldDbEntry{"DST_TRAFFIC_INDEX", 4, fieldToStringUInteger, "BGP Policy Accounting Destination Traffic Index."},
	94: fieldDbEntry{"APPLICATION_DESCRIPTION", -1, fieldToStringASCII, "Application description."},
	95: fieldDbEntry{"APPLICATION_TAG", -1, fieldToStringHex, "8 bits of engine ID, followed by n bits of classification."},
	96: fieldDbEntry{"APPLICATION_NAME", -1, fieldToStringASCII, "Name associated with a classification."},
}

func fieldToUInteger(data []byte) (num uint64) {
	for i := 0; i < len(data) && i < 8; i++ {
		num = (num << 8) | uint64(data[i])
	}
	return num
}

func fieldToStringUInteger(data []byte) string {

	if len(data) > 8 {
		return "int64 overflow"
	}

	return strconv.FormatUint(fieldToUInteger(data), 10)
}

func fieldToStringHex(data []byte) string {
	return "0x" + hex.EncodeToString(data)
}

func fieldToStringASCII(data []byte) string {
	return string(data)
}

func fieldToStringIP(data []byte) string {
	return net.IP(data).String()
}

func fieldToStringMAC(data []byte) string {
	return net.HardwareAddr(data).String()
}

func fieldToStringTCPFlags(data []byte) (flags string) {
	if data[0]&0x80 > 0 {
		flags += "C"
	} else {
		flags += " "
	}
	if data[0]&0x40 > 0 {
		flags += "E"
	} else {
		flags += " "
	}
	if data[0]&0x20 > 0 {
		flags += "U"
	} else {
		flags += " "
	}
	if data[0]&0x10 > 0 {
		flags += "A"
	} else {
		flags += " "
	}
	if data[0]&0x08 > 0 {
		flags += "P"
	} else {
		flags += " "
	}
	if data[0]&0x04 > 0 {
		flags += "R"
	} else {
		flags += " "
	}
	if data[0]&0x02 > 0 {
		flags += "S"
	} else {
		flags += " "
	}
	if data[0]&0x01 > 0 {
		flags += "F"
	} else {
		flags += " "
	}
	return
}

func fieldToStringICMPTypeCode(data []byte) string {
	return fmt.Sprintf("%d/%d", data[0], data[1])
}

func fieldToStringMsecDuration(data []byte) string {
	duration := time.Duration(fieldToUInteger(data)) * time.Millisecond
	return duration.String()
}

func fieldToStringSamplingInterval(data []byte) string {
	return "1 out of " + fieldToStringUInteger(data)
}

func fieldToStringSamplingAlgo(data []byte) string {
	switch data[0] {
	case 0x01:
		return "Deterministic"
	case 0x02:
		return "Random"
	default:
		return "Unknown"
	}
}

func fieldToStringEngineType(data []byte) string {
	switch data[0] {
	case 0x00:
		return "Routing Processor"
	case 0x01:
		return "Linecart"
	default:
		return "Unknown"
	}
}

func fieldToStringMPLSTopLabelType(data []byte) string {
	switch data[0] {
	case 0x01:
		return "TE-MIDPT"
	case 0x02:
		return "ATOM"
	case 0x03:
		return "VPN"
	case 0x04:
		return "BGP"
	case 0x05:
		return "LDP"
	default:
		return "UNKNOWN"
	}
}

func fieldToStringDirection(data []byte) string {
	switch data[0] {
	case 0:
		return "Ingress"
	case 1:
		return "Egress"
	default:
		return "Unknown"
	}
}

func fieldToStringMPLSLabel(bytes []uint8) string {
	var label int
	var exp int
	var bottom int

	label = (int(bytes[0]) << 12) | (int(bytes[1]) << 4) | ((int(bytes[2]) & 0xf0) >> 4)
	exp = int(bytes[2]) & 0x0e
	bottom = int(bytes[0]) & 0x01

	return fmt.Sprintf("%d/%d/%d", label, exp, bottom)
}
