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

func Test_findMember(t *testing.T) {
	typeInt := &btf.Int{Name: "int", Size: 4}

	// struct inner { int x; } is a named struct type, as embedded anonymously with -fms-extensions.
	inner := &btf.Struct{
		Name:    "inner",
		Size:    8,
		Members: []btf.Member{{Name: "x", Type: typeInt, Offset: 32}},
	}

	cases := []struct {
		name           string
		members        []btf.Member
		field          string
		expectedType   btf.Type
		expectedOffset uint32
	}{
		{
			name: "direct_member",
			members: []btf.Member{
				{Name: "a", Type: typeInt, Offset: 0},
				{Name: "b", Type: typeInt, Offset: 64},
			},
			field:          "b",
			expectedType:   typeInt,
			expectedOffset: 8,
		},
		{
			name: "anonymous_union",
			members: []btf.Member{
				{Name: "a", Type: typeInt, Offset: 0},
				{Type: &btf.Union{Size: 4, Members: []btf.Member{
					{Name: "__b", Type: typeInt},
					{Name: "b", Type: typeInt},
				}}, Offset: 256},
			},
			field:          "b",
			expectedType:   typeInt,
			expectedOffset: 32,
		},
		{
			name: "anonymous_struct_nested_in_anonymous_union",
			members: []btf.Member{
				{Type: &btf.Union{Size: 16, Members: []btf.Member{
					{Name: "raw", Type: typeInt},
					{Type: &btf.Struct{Size: 16, Members: []btf.Member{
						{Name: "lo", Type: typeInt, Offset: 0},
						{Name: "hi", Type: typeInt, Offset: 64},
					}}, Offset: 0},
				}}, Offset: 128},
			},
			field:          "hi",
			expectedType:   typeInt,
			expectedOffset: 24,
		},
		{
			name: "anonymous_named_struct",
			members: []btf.Member{
				{Type: inner, Offset: 64},
			},
			field:          "x",
			expectedType:   typeInt,
			expectedOffset: 12,
		},
		{
			name: "anonymous_typedef_struct",
			members: []btf.Member{
				{Type: &btf.Typedef{Name: "inner_t", Type: inner}, Offset: 64},
			},
			field:          "x",
			expectedType:   typeInt,
			expectedOffset: 12,
		},
		{
			name: "named_member_is_not_searched",
			members: []btf.Member{
				{Name: "sub", Type: inner, Offset: 64},
			},
			field:        "x",
			expectedType: nil,
		},
		{
			name: "not_found",
			members: []btf.Member{
				{Name: "a", Type: typeInt},
				{Type: &btf.Union{Members: []btf.Member{{Name: "b", Type: typeInt}}}},
			},
			field:        "c",
			expectedType: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			typ, offset := findMember(c.members, c.field)
			require.Equal(t, c.expectedType, typ, "unexpected member type for field %q", c.field)
			if c.expectedType != nil {
				require.Equal(t, c.expectedOffset, offset, "unexpected byte offset for field %q", c.field)
			}
		})
	}
}

// Test_buildFieldsWithWrap_dentryName checks that dentry->d_name.name resolves to the same
// fetcharg on the layouts before and after Linux 6.18, where d_name moved into an anonymous union.
func Test_buildFieldsWithWrap_dentryName(t *testing.T) {
	typeChar := &btf.Int{Name: "char", Size: 1}
	qstr := &btf.Struct{
		Name: "qstr",
		Size: 16,
		Members: []btf.Member{
			{Name: "hash_len", Type: &btf.Int{Name: "u64", Size: 8}, Offset: 0},
			{Name: "name", Type: &btf.Pointer{Target: &btf.Const{Type: typeChar}}, Offset: 64},
		},
	}
	dParent := btf.Member{Name: "d_parent", Type: &btf.Pointer{}, Offset: 192}

	cases := []struct {
		name   string
		dentry *btf.Struct
	}{
		{
			name: "pre_6_18",
			dentry: &btf.Struct{
				Name: "dentry",
				Size: 192,
				Members: []btf.Member{
					dParent,
					{Name: "d_name", Type: qstr, Offset: 256},
				},
			},
		},
		{
			name: "6_18",
			dentry: &btf.Struct{
				Name: "dentry",
				Size: 192,
				Members: []btf.Member{
					dParent,
					{Type: &btf.Union{Size: 16, Members: []btf.Member{
						{Name: "__d_name", Type: qstr},
						{Name: "d_name", Type: &btf.Const{Type: qstr}},
					}}, Offset: 256},
				},
			},
		},
	}

	regs, err := getRegistersResolver("amd64")
	require.NoError(t, err)

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spec := newMockedBTFSpecWithTypesMap(map[string]btf.Type{"dentry": c.dentry})
			fields := paramFieldsFromNames("dentry", "d_name", "name")

			require.NoError(t, buildFieldsWithWrap(spec, WrapPointer, fields), "building dentry->d_name.name failed")

			fetchArg, err := buildTracingEventFromFields(ProbeTypeKProbe, 0, fields, regs)
			require.NoError(t, err, "building the tracing event failed")
			require.Equal(t, "+40(%di)", fetchArg, "unexpected fetcharg for dentry->d_name.name")
		})
	}
}
