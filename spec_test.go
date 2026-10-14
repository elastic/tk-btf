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
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"
)

func TestSpec(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "test")
	require.NoError(t, err)
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	spec := generateBTFSpec()
	spec.regs, err = getRegistersResolver("arm64")
	require.NoError(t, err)

	c := struct {
		symbolNames              []string
		probes                   []*Probe
		err                      error
		expectedTracingEventStrs []string
	}{
		symbolNames: []string{"test_function_with_ret"},
		probes: []*Probe{
			NewKProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncParamWithName("dentry_param", "d_inode", "i_ino"),
				NewFetchArg("fa2", "u32").FuncParamWithName("dentry_param", "d_inode", "i_ino"),
				NewFetchArg("fa3", "string").FuncParamWithCustomType("dentry_param", WrapPointer, "dentry", "d_inode", "i_ino"),
				NewFetchArg("fa4", "string").FuncParamArbitrary(1, WrapStructPointer, "dentry", "d_inode", "i_ino"),
				NewFetchArg("fa5", "string").FuncParamArbitrary(1, WrapPointer, "dentry", "d_inode", "i_ino"),
				NewFetchArg("fa6", "string").FuncParamArbitrary(1, WrapNone, "dentry", "d_inode", "i_ino"),
				NewFetchArg("fa7", "u32").FuncParamWithName("tsk_param", "", "numbers", "enum:an_enum:ENUM_VAL_2", "val"),
			),
			NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncReturn("d_inode", "i_ino"),
				NewFetchArg("fa2", "u32").FuncReturnArbitrary(WrapStructPointer, "dentry", "d_inode", "i_ino"),
			),
		},
		err: nil,
		expectedTracingEventStrs: []string{
			"fa1=+64(+48(%x0)):u32 fa2=+64(+48(%x0)):u32 fa3=+0(+64(+48(%x0))):string fa4=+0(+64(+48(+0(%x1)))):string fa5=+0(+64(+48(%x1))):string fa6=+0(+64(+48(%x1))):string fa7=+1(+48(+4(%x2))):u32",
			"fa1=+64(+48(%x0)):u32 fa2=+64(+48(+0(%x0))):u32",
		},
	}

	symbol := NewSymbol(c.symbolNames...).AddProbes(c.probes...)

	err = spec.BuildSymbol(symbol)
	require.ErrorIs(t, err, c.err)
	for index, p := range symbol.GetProbes() {
		require.Equal(t, c.expectedTracingEventStrs[index], p.GetTracingEventProbe())
	}

	fileName := filepath.Join(tmpDir, "btfFile")
	err = spec.StripAndSave(fileName, symbol)
	require.NoError(t, err)

	// load stripped spec from path; NOTE this an actual implementation of *btf.Spec
	pathSpec, err := NewSpecFromPath(fileName, &SpecOptions{
		arch: "arm64",
	})
	require.NoError(t, err)
	// check that qstr is actually stripped
	_, err = pathSpec.spec.AnyTypesByName("qstr")
	require.ErrorIs(t, err, btf.ErrNotFound)
	// check that dentry is not stripped
	_, err = pathSpec.spec.AnyTypesByName("dentry")
	require.NoError(t, err)
	// check that inode is not stripped
	_, err = pathSpec.spec.AnyTypesByName("inode")
	require.NoError(t, err)
	// build symbol with the new spec
	err = pathSpec.BuildSymbol(symbol)
	require.ErrorIs(t, err, c.err)
	for index, p := range symbol.GetProbes() {
		require.Equal(t, c.expectedTracingEventStrs[index], p.GetTracingEventProbe())
	}

	// re-strip it and save it
	err = pathSpec.StripAndSave(fileName, symbol)
	require.NoError(t, err)

	// load re-stripped spec from reader; NOTE this an actual implementation of *btf.Spec
	file, err := os.Open(fileName)
	require.NoError(t, err)

	defer func() {
		_ = file.Close()
	}()

	readerSpec, err := NewSpecFromReader(file, &SpecOptions{
		arch: "arm64",
	})
	require.NoError(t, err)
	// check that qstr is actually stripped
	_, err = readerSpec.spec.AnyTypesByName("qstr")
	require.ErrorIs(t, err, btf.ErrNotFound)
	// check that dentry is not stripped
	_, err = readerSpec.spec.AnyTypesByName("dentry")
	require.NoError(t, err)
	// check that inode is not stripped
	_, err = readerSpec.spec.AnyTypesByName("inode")
	require.NoError(t, err)
	// build symbol with the new spec
	err = readerSpec.BuildSymbol(symbol)
	require.ErrorIs(t, err, c.err)
	for index, p := range symbol.GetProbes() {
		require.Equal(t, c.expectedTracingEventStrs[index], p.GetTracingEventProbe())
	}
}

func TestSpec_ContainsSymbol(t *testing.T) {
	mockSpec := &Spec{
		spec: newMockedBTFSpecWithTypesMap(map[string]btf.Type{
			"dentry": &btf.Func{},
		}),
		regs: nil,
	}

	require.False(t, mockSpec.ContainsSymbol("unknown"))
	require.True(t, mockSpec.ContainsSymbol("dentry"))
}

func TestSpec_AnyTypesByName(t *testing.T) {
	mockSpec := &Spec{
		spec: newMockedBTFSpecWithTypesMap(map[string]btf.Type{
			"dentry": &btf.Func{},
		}),
		regs: nil,
	}

	foundTypes, err := mockSpec.AnyTypesByName("dentry")
	require.NoError(t, err)
	require.Len(t, foundTypes, 1)
}

// TestSpec_StripAndSave_anonymousMember checks that a field inside an anonymous union (dentry.d_name
// since Linux 6.18) survives StripAndSave, and that the anonymous union is stripped like any other type.
func TestSpec_StripAndSave_anonymousMember(t *testing.T) {
	typeInt := &btf.Int{Name: "int", Size: 4}
	typeChar := &btf.Int{Name: "char", Size: 1}
	qstr := &btf.Struct{
		Name: "qstr",
		Size: 16,
		Members: []btf.Member{
			{Name: "hash_len", Type: &btf.Int{Name: "u64", Size: 8}, Offset: 0},
			{Name: "name", Type: &btf.Pointer{Target: &btf.Const{Type: typeChar}}, Offset: 64},
		},
	}
	nameUnion := &btf.Union{Size: 16, Members: []btf.Member{
		{Name: "__d_name", Type: qstr},
		{Name: "d_name", Type: &btf.Const{Type: qstr}},
	}}
	otherUnion := &btf.Union{Size: 4, Members: []btf.Member{
		{Name: "u_a", Type: typeInt},
		{Name: "u_b", Type: typeInt},
	}}
	dentry := &btf.Struct{
		Name: "dentry",
		Size: 64,
		Members: []btf.Member{
			{Name: "d_flags", Type: typeInt, Offset: 0},
			{Type: nameUnion, Offset: 256},
			{Type: otherUnion, Offset: 384},
		},
	}
	proto := &btf.FuncProto{
		Return: typeInt,
		Params: []btf.FuncParam{{Name: "dentry_param", Type: &btf.Pointer{Target: dentry}}},
	}

	spec := &Spec{
		spec: newMockedBTFSpecWithTypesMap(map[string]btf.Type{
			"int":                 typeInt,
			"char":                typeChar,
			"qstr":                qstr,
			"dentry_name_union":   nameUnion,
			"dentry_other_union":  otherUnion,
			"dentry":              dentry,
			"test_function_proto": proto,
			"test_function":       &btf.Func{Name: "test_function", Type: proto},
		}),
		regs: &registersAmd64{},
	}

	const expected = "n=+0(+40(%di)):string"
	symbol := NewSymbol("test_function").AddProbes(
		NewKProbe().AddFetchArgs(NewFetchArg("n", "string").FuncParamWithName("dentry_param", "d_name", "name")),
	)

	// strippedLayout returns the member names of dentry and of its anonymous members.
	strippedLayout := func(t *testing.T, s *Spec) []string {
		types, err := s.spec.AnyTypesByName("dentry")
		require.NoError(t, err, "dentry is missing from the stripped spec")
		require.Len(t, types, 1, "expected exactly one dentry type")

		var layout []string
		for _, m := range types[0].(*btf.Struct).Members {
			if u, ok := m.Type.(*btf.Union); ok && m.Name == "" {
				for _, um := range u.Members {
					layout = append(layout, "anon."+um.Name)
				}
				continue
			}
			layout = append(layout, m.Name)
		}
		return layout
	}

	require.NoError(t, spec.BuildSymbol(symbol), "building on the full spec failed")
	require.Equal(t, expected, symbol.GetProbes()[0].GetTracingEventProbe(), "unexpected fetcharg on the full spec")

	fileName := filepath.Join(t.TempDir(), "btfFile")
	require.NoError(t, spec.StripAndSave(fileName, symbol), "stripping the full spec failed")

	pathSpec, err := NewSpecFromPath(fileName, &SpecOptions{arch: "amd64"})
	require.NoError(t, err, "loading the stripped spec failed")
	require.Equal(t, []string{"anon.d_name"}, strippedLayout(t, pathSpec), "unexpected dentry layout after stripping")

	require.NoError(t, pathSpec.BuildSymbol(symbol), "building on the stripped spec failed")
	require.Equal(t, expected, symbol.GetProbes()[0].GetTracingEventProbe(), "unexpected fetcharg on the stripped spec")

	// re-strip the stripped spec, which is an actual *btf.Spec, and load it again
	require.NoError(t, pathSpec.StripAndSave(fileName, symbol), "re-stripping the stripped spec failed")

	file, err := os.Open(fileName)
	require.NoError(t, err)
	defer func() {
		_ = file.Close()
	}()

	readerSpec, err := NewSpecFromReader(file, &SpecOptions{arch: "amd64"})
	require.NoError(t, err, "loading the re-stripped spec failed")
	require.Equal(t, []string{"anon.d_name"}, strippedLayout(t, readerSpec), "unexpected dentry layout after re-stripping")

	require.NoError(t, readerSpec.BuildSymbol(symbol), "building on the re-stripped spec failed")
	require.Equal(t, expected, symbol.GetProbes()[0].GetTracingEventProbe(), "unexpected fetcharg on the re-stripped spec")
}
