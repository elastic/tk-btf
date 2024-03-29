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
