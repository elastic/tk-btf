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
	"runtime"
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
	spec.regs, err = getRegistersResolver(runtime.GOARCH)
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
			),
			NewKRetProbe().AddFetchArgs(
				NewFetchArg("fa1", "u32").FuncReturn("d_inode", "i_ino"),
				NewFetchArg("fa2", "u32").FuncReturnArbitrary(WrapStructPointer, "dentry", "d_inode", "i_ino"),
			),
		},
		err: nil,
		expectedTracingEventStrs: []string{
			"fa1=+64(+48(%x0)):u32 fa2=+64(+48(%x0)):u32 fa3=+0(+64(+48(%x0))):string fa4=+0(+64(+48(+0(%x1)))):string fa5=+0(+64(+48(%x1))):string fa6=+0(+64(+48(%x1))):string",
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
	pathSpec, err := NewSpecFromPath(fileName, nil)
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

	readerSpec, err := NewSpecFromReader(file, nil)
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
