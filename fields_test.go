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

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
)

func Test_buildFieldsWithWrap(t *testing.T) {

	cases := []struct {
		name           string
		wrap           Wrap
		fields         []*field
		index          int
		anyTypesByName []btf.Type
		err            error
		destType       btf.Type
	}{
		{
			name:   "any_types_by_name_struct_prioritization",
			wrap:   WrapNone,
			fields: paramFieldsFromNames("dentry"),
			index:  0,
			anyTypesByName: []btf.Type{
				&btf.Int{
					Name: "dentry",
				},
				&btf.Struct{
					Name: "dentry",
				},
				&btf.Func{
					Name: "dentry",
				},
			},
			err:      nil,
			destType: &btf.Struct{},
		},
		{
			name:   "no_fields_specified",
			wrap:   WrapNone,
			fields: nil,
			index:  0,
			anyTypesByName: []btf.Type{
				&btf.Int{
					Name: "dentry",
				},
				&btf.Struct{
					Name: "dentry",
				},
				&btf.Func{
					Name: "dentry",
				},
			},
			err:      ErrMissingFields,
			destType: &btf.Struct{},
		},
		{
			name:   "any_types_by_name_multiple_types_no_struct",
			wrap:   WrapNone,
			fields: paramFieldsFromNames("dentry"),
			index:  0,
			anyTypesByName: []btf.Type{
				&btf.Int{
					Name: "dentry",
				},
				&btf.Func{
					Name: "dentry",
				},
			},
			err:      nil,
			destType: &btf.Int{},
		},
		{
			name:           "any_types_by_name_zero_types",
			wrap:           WrapNone,
			fields:         paramFieldsFromNames("dentry"),
			index:          0,
			anyTypesByName: []btf.Type{},
			err:            ErrFieldNotFound,
			destType:       nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := mockAnyTypesByNameOnAnything(c.anyTypesByName, c.err)
			err := buildFieldsWithWrap(spec, c.wrap, c.fields)
			require.ErrorIs(t, err, c.err)

			if c.fields != nil {
				require.IsType(t, c.destType, c.fields[0].btfType)
			}
		})
	}
}

func Test_getArrayTypeSizeBytes(t *testing.T) {
	cases := []struct {
		name              string
		btfArray          *btf.Array
		expectedSizeBytes uint32
	}{
		{
			name: "int_type",
			btfArray: &btf.Array{
				Type: &btf.Int{
					Size: 8,
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 8,
		}, {
			name: "union_type",
			btfArray: &btf.Array{
				Type: &btf.Union{
					Size: 32,
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 32,
		}, {
			name: "struct_type",
			btfArray: &btf.Array{
				Type: &btf.Struct{
					Size: 48,
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 48,
		}, {
			name: "float_type",
			btfArray: &btf.Array{
				Type: &btf.Float{
					Size: 8,
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 8,
		}, {
			name: "enum_type",
			btfArray: &btf.Array{
				Type: &btf.Enum{
					Size: 24,
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 24,
		}, {
			name: "datasec_type",
			btfArray: &btf.Array{
				Type: &btf.Datasec{
					Size: 24,
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 24,
		}, {
			name: "typedef_type",
			btfArray: &btf.Array{
				Type: &btf.Typedef{
					Type: &btf.Struct{
						Size: 24,
					},
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 24,
		}, {
			name: "const_type",
			btfArray: &btf.Array{
				Type: &btf.Const{
					Type: &btf.Struct{
						Size: 24,
					},
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 24,
		}, {
			name: "pointer_type",
			btfArray: &btf.Array{
				Type: &btf.Pointer{
					Target: &btf.Pointer{
						Target: &btf.Struct{
							Size: 24,
						},
					},
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 8,
		}, {
			name: "void_type",
			btfArray: &btf.Array{
				Type: &btf.Void{},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 0,
		}, {
			name: "pointer_void_type",
			btfArray: &btf.Array{
				Type: &btf.Pointer{
					Target: &btf.Void{},
				},
				Index: &btf.Int{
					Size: 4,
				},
				Nelems: 3,
			},
			expectedSizeBytes: 8,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sizeBytes := getArrayTypeSizeBytes(c.btfArray.Type)
			require.Equal(t, c.expectedSizeBytes, sizeBytes)
		})
	}
}
