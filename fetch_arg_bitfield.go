// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package tkbtf

import (
	"fmt"
	"math/bits"
)

// BitFieldTypeMask generates the string representation of a bitfield fetchArg type based on the given mask value
// (https://docs.kernel.org/trace/kprobetrace.html#types). Specifically, it dynamically determines the leading zeros,
// ones count, and size of container based on the mask (supported types are uint8, uint16, uint32, or uint64) and performs
// the necessary calculations to build the respective string representation of a bitfield type. When this type
// is assigned to a fetchArg, it causes only the bits of the fetch arg value that fall withing the original mask
// to remain (ret := fetchArgValue & mask) and then be shifted all the way to the right (ret := ret >> maskTrailingZeros).
// The bitfield type has a format of "b{bitWidth}@{bitOffset}/{containerSize}".
//
// Note: masks without consecutive ones (e.g. 0x5) are not supported and their behavior is undefined.
func BitFieldTypeMask[T interface {
	uint8 | uint16 | uint32 | uint64
}](mask T) string {
	var (
		leadingZeros      int // Number of leading zeros in the mask
		onesCount         int // Number of set bits (ones) in the mask
		containerSizeBits int // Size of the container in bits (8, 16, 32, or 64)
	)

	// Determine the type of the mask and perform the necessary calculations based on it
	switch maskWithType := any(mask).(type) {
	case uint8:
		leadingZeros = bits.LeadingZeros8(maskWithType)
		onesCount = bits.OnesCount8(maskWithType)
		containerSizeBits = 8
	case uint16:
		leadingZeros = bits.LeadingZeros16(maskWithType)
		onesCount = bits.OnesCount16(maskWithType)
		containerSizeBits = 16
	case uint32:
		leadingZeros = bits.LeadingZeros32(maskWithType)
		onesCount = bits.OnesCount32(maskWithType)
		containerSizeBits = 32
	case uint64:
		leadingZeros = bits.LeadingZeros64(maskWithType)
		onesCount = bits.OnesCount64(maskWithType)
		containerSizeBits = 64
	}

	// Calculate the bit offset and a bit width
	bo := containerSizeBits - onesCount - leadingZeros
	bw := onesCount

	// Create and return the string representation of the bit field type
	return fmt.Sprintf("b%d@%d/%d", bw, bo, containerSizeBits)
}
