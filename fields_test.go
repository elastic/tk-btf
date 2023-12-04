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
			require.IsType(t, c.destType, c.fields[0].btfType)
		})
	}
}
