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

func TestProbes(t *testing.T) {
	spec := generateBTFSpec()

	cases := []struct {
		name               string
		symbolNames        []string
		skipValidation     bool
		probe              *Probe
		expectedSymbol     string
		expectedID         string
		expectedType       ProbeType
		expectedTracingStr string
		expectedFilterStr  string
		err                error
	}{
		{
			name:        "kprobe_named_param",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "d_inode", "i_ino"),
				NewFetchArg("fa2", "string").FuncParamWithName("dentry_param", "d_name", "name"),
				NewFetchArg("fa3", "u32").FuncParamWithName("inode_param", "i_ino"),
			),
			expectedSymbol:     "test_function",
			expectedID:         "kprobe_test_function",
			expectedType:       ProbeTypeKProbe,
			expectedTracingStr: "fa1=+64(+48(%di)):u32 fa2=+0(+40(%di)):string fa3=+64(%si):u32",
			err:                nil,
		},
		{
			name:        "kprobe_duplicate_fetch_arg",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "d_inode", "i_ino"),
				NewFetchArg("fa1", "string").FuncParamWithName("dentry_param", "d_name", "name"),
			),
			err: ErrDuplicateFetchArgs,
		},
		{
			name:        "kprobe_index_param",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamArbitrary(0, WrapNone, "dentry", "d_inode", "i_ino"),
				NewFetchArg("fa2", "string").FuncParamArbitrary(0, WrapNone, "dentry", "d_name", "name"),
				NewFetchArg("fa3", "u32").FuncParamArbitrary(1, WrapNone, "inode", "i_ino"),
				NewFetchArg("fa4", "u32").FuncParamArbitrary(1, WrapPointer, "dentry", "d_inode", "i_ino"),
				NewFetchArg("fa5", "u32").FuncParamArbitrary(0, WrapStructPointer, "dentry", "d_inode", "i_ino"),
			),
			expectedSymbol:     "test_function",
			expectedID:         "kprobe_test_function",
			expectedType:       ProbeTypeKProbe,
			expectedTracingStr: "fa1=+64(+48(%di)):u32 fa2=+0(+40(%di)):string fa3=+64(%si):u32 fa4=+64(+48(%si)):u32 fa5=+64(+48(+0(%di))):u32",
			err:                nil,
		},
		{
			name:        "kprobe_custom_type_param",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithCustomType("dentry_param", WrapNone, "inode", "i_ino"),
				NewFetchArg("fa2", "u32").FuncParamWithCustomType("dentry_param", WrapPointer, "inode", "i_ino"),
				NewFetchArg("fa3", "string").FuncParamWithCustomType("dentry_param", WrapStructPointer, "inode", "i_ino"),
			),
			expectedSymbol:     "test_function",
			expectedID:         "kprobe_test_function",
			expectedType:       ProbeTypeKProbe,
			expectedTracingStr: "fa1=+64(%di):u32 fa2=+64(%di):u32 fa3=+0(+64(+0(%di))):string",
			err:                nil,
		},
		{
			name:        "kprobe_unsupported_wrap_type",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithCustomType("dentry_param", 10000, "inode", "i_ino"),
			),
			err: ErrUnsupportedWrapType,
		},
		{
			name:        "kprobe_func_param_not_found",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("unknown", "inode", "i_ino"),
			),
			err: ErrFuncParamNotFound,
		},
		{
			name:        "kprobe_param_field_not_found_param_named",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "unknown", "i_ino"),
			),
			err: ErrFieldNotFound,
		},
		{
			name:        "kprobe_param_field_not_found_param_at_index",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamArbitrary(0, WrapNone, "dentry_param", "unknown", "i_ino"),
			),
			err: ErrFieldNotFound,
		},
		{
			name:        "kprobe_multiple_params",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "string").
					FuncParamWithName("unknown", "d_inode", "i_ino").
					FuncParamWithCustomType("unknown", WrapNone, "inode", "i_ino").
					FuncParamArbitrary(0, WrapNone, "dentry", "d_name", "name"),
			),
			expectedSymbol:     "test_function",
			expectedID:         "kprobe_test_function",
			expectedType:       ProbeTypeKProbe,
			expectedTracingStr: "fa1=+0(+40(%di)):string",
			err:                nil,
		},
		{
			name:        "kprobe_multiple_symbols",
			symbolNames: []string{"unknown_function", "test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "d_inode", "i_ino"),
				NewFetchArg("fa2", "string").FuncParamWithName("dentry_param", "d_name", "name"),
				NewFetchArg("fa3", "u32").FuncParamWithName("inode_param", "i_ino"),
			),
			expectedSymbol:     "test_function",
			expectedID:         "kprobe_test_function",
			expectedType:       ProbeTypeKProbe,
			expectedTracingStr: "fa1=+64(+48(%di)):u32 fa2=+0(+40(%di)):string fa3=+64(%si):u32",
			err:                nil,
		},
		{
			name:        "kprobe_unknown_symbols",
			symbolNames: []string{"unknown_function_1", "unknown_function_2"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "d_inode", "i_ino"),
				NewFetchArg("fa2", "string").FuncParamWithName("dentry_param", "d_name", "name"),
				NewFetchArg("fa3", "u32").FuncParamWithName("inode_param", "i_ino"),
			),
			err: ErrSymbolNotFound,
		},
		{
			name:        "kprobe_set_id",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "d_inode", "i_ino"),
				NewFetchArg("fa2", "string").FuncParamWithName("dentry_param", "d_name", "name"),
				NewFetchArg("fa3", "u32").FuncParamWithName("inode_param", "i_ino"),
			).SetRef("test_probe_id"),
			expectedSymbol:     "test_function",
			expectedID:         "kprobe_test_probe_id",
			expectedType:       ProbeTypeKProbe,
			expectedTracingStr: "fa1=+64(+48(%di)):u32 fa2=+0(+40(%di)):string fa3=+64(%si):u32",
			err:                nil,
		},
		{
			name:        "kretprobe_without_params",
			symbolNames: []string{"test_function"},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncReturn(),
			),
			expectedSymbol:     "test_function",
			expectedID:         "kretprobe_test_function",
			expectedType:       ProbeTypeKRetProbe,
			expectedTracingStr: "fa1=%ax:u32",
			err:                nil,
		},
		{
			name:        "kretprobe_with_param_return",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncReturn("d_inode", "i_ino"),
			),
			expectedSymbol:     "test_function_with_ret",
			expectedID:         "kretprobe_test_function_with_ret",
			expectedType:       ProbeTypeKRetProbe,
			expectedTracingStr: "fa1=+64(+48(%ax)):u32",
			err:                nil,
		},
		{
			name:        "kretprobe_with_param_return_custom_type",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncReturnArbitrary(WrapNone, "dentry", "d_inode", "i_ino"),
			),
			expectedSymbol:     "test_function_with_ret",
			expectedID:         "kretprobe_test_function_with_ret",
			expectedType:       ProbeTypeKRetProbe,
			expectedTracingStr: "fa1=+64(+48(%ax)):u32",
			err:                nil,
		},
		{
			name:        "kprobe_set_filter",
			symbolNames: []string{"test_function"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "d_inode", "i_ino"),
				NewFetchArg("fa2", "string").FuncParamWithName("dentry_param", "d_name", "name"),
				NewFetchArg("fa3", "u32").FuncParamWithName("inode_param", "i_ino"),
			).SetFilter("fa1==1"),
			expectedSymbol:     "test_function",
			expectedID:         "kprobe_test_function",
			expectedType:       ProbeTypeKProbe,
			expectedTracingStr: "fa1=+64(+48(%di)):u32 fa2=+0(+40(%di)):string fa3=+64(%si):u32",
			expectedFilterStr:  "fa1==1",
			err:                nil,
		},
		{
			name:        "kretprobe_set_filter",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncReturnArbitrary(WrapNone, "dentry", "d_inode", "i_ino"),
			).SetFilter("fa1==1"),
			expectedSymbol:     "test_function_with_ret",
			expectedID:         "kretprobe_test_function_with_ret",
			expectedType:       ProbeTypeKRetProbe,
			expectedTracingStr: "fa1=+64(+48(%ax)):u32",
			expectedFilterStr:  "fa1==1",
			err:                nil,
		},
		{
			name:        "kprobe_without_symbol_validation",
			symbolNames: []string{"unknown_test_function"},

			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamArbitrary(0, WrapNone, "dentry", "d_inode", "i_ino"),
				NewFetchArg("fa2", "string").FuncParamArbitrary(0, WrapNone, "dentry", "d_name", "name"),
				NewFetchArg("fa3", "u32").FuncParamArbitrary(1, WrapNone, "inode", "i_ino"),
				NewFetchArg("fa4", "u32").FuncParamArbitrary(1, WrapPointer, "dentry", "d_inode", "i_ino"),
				NewFetchArg("fa5", "u32").FuncParamArbitrary(0, WrapStructPointer, "dentry", "d_inode", "i_ino"),
			),
			skipValidation:     true,
			expectedSymbol:     "unknown_test_function",
			expectedID:         "kprobe_unknown_test_function",
			expectedType:       ProbeTypeKProbe,
			expectedTracingStr: "fa1=+64(+48(%di)):u32 fa2=+0(+40(%di)):string fa3=+64(%si):u32 fa4=+64(+48(%si)):u32 fa5=+64(+48(+0(%di))):u32",
			err:                nil,
		},
		{
			name:        "kprobe_incompatible_fetch_arg_1",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncReturn("dentry"),
			),
			err: ErrIncompatibleFetchArg,
		},
		{
			name:        "kprobe_incompatible_fetch_arg_2",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncReturnArbitrary(WrapNone, "dentry"),
			),
			err: ErrIncompatibleFetchArg,
		},
		{
			name:        "kretprobe_incompatible_fetch_arg_1",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamArbitrary(0, WrapNone, "dentry"),
			),
			err: ErrIncompatibleFetchArg,
		},
		{
			name:        "kretprobe_incompatible_fetch_arg_2",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithCustomType("dentry_param", WrapNone, "dentry"),
			),
			err: ErrIncompatibleFetchArg,
		},
		{
			name:        "kretprobe_incompatible_fetch_arg_3",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "dentry"),
			),
			err: ErrIncompatibleFetchArg,
		},
		{
			name:        "kretprobe_without_field_builders",
			symbolNames: []string{"test_function_with_ret"},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32"),
			),
			err: ErrMissingFieldBuilders,
		},
		{
			name:        "kprobe_empty_names",
			symbolNames: []string{"   ", "    "},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32"),
			),
			err: ErrMissingSymbolNames,
		},
		{
			name:        "kprobe_missing_names",
			symbolNames: nil,
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32"),
			),
			err: ErrMissingSymbolNames,
		},
		{
			name:        "kprobe_without_validation_missing_name",
			symbolNames: []string{"   "},
			probe: NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32"),
			),
			skipValidation: true,
			err:            ErrMissingSymbolNames,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var symbol *Symbol
			if c.skipValidation {
				symbol = NewSymbolWithoutValidation(c.symbolNames[0]).AddProbes(c.probe)
			} else {
				symbol = NewSymbol(c.symbolNames...).AddProbes(c.probe)
			}

			err := spec.BuildSymbol(symbol)
			require.ErrorIs(t, err, c.err)

			if c.err != nil {
				return
			}

			require.Equal(t, c.expectedTracingStr, c.probe.GetTracingEventProbe())
			require.Equal(t, c.expectedFilterStr, c.probe.GetTracingEventFilter())
			require.Equal(t, c.expectedSymbol, c.probe.GetSymbolName())
			require.Equal(t, c.expectedType, c.probe.GetType())
			require.Equal(t, c.expectedID, c.probe.GetID())
			require.True(t, symbol.GetProbes()[0] == c.probe)
		})
	}
}
