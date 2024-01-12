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

func Test_getRegistersResolver(t *testing.T) {

	cases := []struct {
		arch string
		err  error
	}{
		{
			arch: "amd64",
			err:  nil,
		},
		{
			arch: "arm64",
			err:  nil,
		},
		{
			arch: "unknown",
			err:  ErrUnsupportedArch,
		},
	}

	for _, c := range cases {
		t.Run(c.arch, func(t *testing.T) {
			regs, err := getRegistersResolver(c.arch)
			switch {
			case c.err != nil:
				require.Nil(t, regs)
			case c.err == nil:
				require.NotNil(t, regs)
			}
			require.ErrorIs(t, err, c.err)
		})
	}
}

func TestRegistersAmd64_GetFuncParamRegister(t *testing.T) {
	regs, err := getRegistersResolver("amd64")
	require.NoError(t, err)

	cases := []struct {
		name       string
		reg        string
		paramIndex int
		err        error
	}{
		{
			name:       "amd64_param_0",
			reg:        "%di",
			paramIndex: 0,
			err:        nil,
		},
		{
			name:       "amd64_param_1",
			reg:        "%si",
			paramIndex: 1,
			err:        nil,
		},
		{
			name:       "amd64_param_2",
			reg:        "%dx",
			paramIndex: 2,
			err:        nil,
		},
		{
			name:       "amd64_param_3",
			reg:        "%cx",
			paramIndex: 3,
			err:        nil,
		},
		{
			name:       "amd64_param_4",
			reg:        "%r8",
			paramIndex: 4,
			err:        nil,
		},
		{
			name:       "amd64_param_5",
			reg:        "%r9",
			paramIndex: 5,
			err:        nil,
		},
		{
			name:       "amd64_param_6",
			reg:        "",
			paramIndex: 6,
			err:        ErrUnsupportedFuncParamIndex,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg, err := regs.GetFuncParamRegister(c.paramIndex)
			require.Equal(t, c.reg, reg)
			require.ErrorIs(t, err, c.err)
		})
	}
}

func TestRegistersAmd64_GetReturnRegister(t *testing.T) {
	regs, err := getRegistersResolver("amd64")
	require.NoError(t, err)

	require.Equal(t, regs.GetFuncReturnRegister(), "%ax")
}

func TestRegistersArm64_GetFuncParamRegister(t *testing.T) {
	regs, err := getRegistersResolver("arm64")
	require.NoError(t, err)

	cases := []struct {
		name       string
		reg        string
		paramIndex int
		err        error
	}{
		{
			name:       "arm64_param_0",
			reg:        "%x0",
			paramIndex: 0,
			err:        nil,
		},
		{
			name:       "arm64_param_1",
			reg:        "%x1",
			paramIndex: 1,
			err:        nil,
		},
		{
			name:       "arm64_param_2",
			reg:        "%x2",
			paramIndex: 2,
			err:        nil,
		},
		{
			name:       "arm64_param_3",
			reg:        "%x3",
			paramIndex: 3,
			err:        nil,
		},
		{
			name:       "arm64_param_4",
			reg:        "%x4",
			paramIndex: 4,
			err:        nil,
		},
		{
			name:       "arm64_param_5",
			reg:        "%x5",
			paramIndex: 5,
			err:        nil,
		},
		{
			name:       "arm64_param_6",
			reg:        "",
			paramIndex: 6,
			err:        ErrUnsupportedFuncParamIndex,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			reg, err := regs.GetFuncParamRegister(c.paramIndex)
			require.Equal(t, c.reg, reg)
			require.ErrorIs(t, err, c.err)
		})
	}
}

func TestRegistersArm64_GetReturnRegister(t *testing.T) {
	regs, err := getRegistersResolver("arm64")
	require.NoError(t, err)

	require.Equal(t, regs.GetFuncReturnRegister(), "%x0")
}
