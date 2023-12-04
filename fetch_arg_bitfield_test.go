package tkbtf

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBitFieldTypeMask(t *testing.T) {

	bitFieldType := BitFieldTypeMask(uint8(0x4))
	require.Equal(t, "b1@2/8", bitFieldType)

	bitFieldType = BitFieldTypeMask(uint16(0x4))
	require.Equal(t, "b1@2/16", bitFieldType)

	bitFieldType = BitFieldTypeMask(uint32(0x4))
	require.Equal(t, "b1@2/32", bitFieldType)

	bitFieldType = BitFieldTypeMask(uint64(0x4))
	require.Equal(t, "b1@2/64", bitFieldType)
}
