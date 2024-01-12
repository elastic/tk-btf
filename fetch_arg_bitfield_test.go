package tkbtf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitFieldTypeMask(t *testing.T) {

	bitFieldType := BitFieldTypeMask(uint8(0b100))
	require.Equal(t, "b1@2/8", bitFieldType)

	bitFieldType = BitFieldTypeMask(uint16(0b100))
	require.Equal(t, "b1@2/16", bitFieldType)

	bitFieldType = BitFieldTypeMask(uint32(0b100))
	require.Equal(t, "b1@2/32", bitFieldType)

	bitFieldType = BitFieldTypeMask(uint64(0b100))
	require.Equal(t, "b1@2/64", bitFieldType)

	bitFieldType = BitFieldTypeMask(uint32(0b111100000))
	require.Equal(t, "b4@5/32", bitFieldType)
}
