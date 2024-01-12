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
