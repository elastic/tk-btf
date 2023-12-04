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
			arch: "386",
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

func TestRegisters386_GetFuncParamRegister(t *testing.T) {
	regs, err := getRegistersResolver("386")
	require.NoError(t, err)

	cases := []struct {
		name       string
		reg        string
		paramIndex int
		err        error
	}{
		{
			name:       "386_param_0",
			reg:        "%ax",
			paramIndex: 0,
			err:        nil,
		},
		{
			name:       "386_param_1",
			reg:        "%dx",
			paramIndex: 1,
			err:        nil,
		},
		{
			name:       "386_param_2",
			reg:        "%cx",
			paramIndex: 2,
			err:        nil,
		},
		{
			name:       "386_param_3",
			reg:        "$stack1",
			paramIndex: 3,
			err:        nil,
		},
		{
			name:       "386_param_4",
			reg:        "$stack2",
			paramIndex: 4,
			err:        nil,
		},
		{
			name:       "386_param_5",
			reg:        "$stack3",
			paramIndex: 5,
			err:        nil,
		},
		{
			name:       "386_param_6",
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

func TestRegisters386_GetReturnRegister(t *testing.T) {
	regs, err := getRegistersResolver("386")
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
