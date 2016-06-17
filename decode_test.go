package nf9packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDecodeValidHeader(t *testing.T) {
	data := []byte{
		0x00, 0x09, // Version
		0x00, 0x00, // Records count
		0x00, 0x00, 0x01, 0x00, // System uptime in milliseconds (256)
		0x00, 0x00, 0x02, 0x00, // Timestamp (512)
		0x00, 0x00, 0x04, 0x00, // Sequence number (1024)
		0x00, 0x00, 0x08, 0x00, // Source ID (2048)
	}
	expected := Packet{
		Version:        9,
		Count:          0,
		SysUpTime:      256,
		UnixSecs:       512,
		SequenceNumber: 1024,
		SourceId:       2048,
		FlowSets:       []interface{}{},
	}

	actual, err := Decode(data)
	require.NoError(t, err)
	assert.Equal(t, &expected, actual)
}

func TestDecodeIncompleteHeader(t *testing.T) {
	data := []byte{
		0x00, 0x09, // Version
		0x00, 0x00, // Records count
		0x00, 0x00, 0x01, 0x00, // System uptime in milliseconds (256)
		0x00, 0x00, 0x02, 0x00, // Timestamp (512)
		0x00, 0x00, 0x04, 0x00, // Sequence number (1024)
		0x00, 0x00, 0x08, // Source ID, missing single byte
	}

	actual, err := Decode(data)
	assert.Error(t, err)
	assert.Nil(t, actual)
}

func TestDecodeEmptyPacket(t *testing.T) {
	actual, err := Decode(nil)
	assert.Error(t, err)
	assert.Nil(t, actual)

	actual, err = Decode([]byte{})
	assert.Error(t, err)
	assert.Nil(t, actual)

}
