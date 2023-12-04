package tkbtf

import (
	"fmt"
)

// registersResolver is an interface that abstracts all the different per architecture
// implementations of registersResolver.
type registersResolver interface {
	// GetFuncParamRegister returns the architecture-specific string representation of register that corresponds
	// to the given parameter index. If the index is invalid, it returns an empty string
	// and an error.
	GetFuncParamRegister(index int) (string, error)

	// GetFuncReturnRegister returns the architecture-specific string representation of the register that corresponds
	// to a function return value.
	GetFuncReturnRegister() string
}

// getRegistersResolver returns the architecture-specific registersResolver. If the given architecture is not
// supported, it returns ErrUnsupportedArch.
func getRegistersResolver(arch string) (registersResolver, error) {
	switch arch {
	case "amd64":
		return &registersAmd64{}, nil
	case "arm64":
		return &registersArm64{}, nil
	case "386":
		return &registers386{}, nil
	default:
		return nil, fmt.Errorf("%s not supported: %w", arch, ErrUnsupportedArch)
	}
}

// registersAmd64 is the registersResolver implementation for amd64 architecture
type registersAmd64 struct{}

func (*registersAmd64) GetFuncParamRegister(index int) (string, error) {
	switch index {
	case 0:
		return "%di", nil
	case 1:
		return "%si", nil
	case 2:
		return "%dx", nil
	case 3:
		return "%cx", nil
	case 4:
		return "%r8", nil
	case 5:
		return "%r9", nil
	default:
		return "", ErrUnsupportedFuncParamIndex
	}
}

func (*registersAmd64) GetFuncReturnRegister() string {
	return "%ax"
}

// registersArm64 is the registersResolver implementation for arm64 architecture
type registersArm64 struct{}

func (*registersArm64) GetFuncParamRegister(paramIndex int) (string, error) {
	switch paramIndex {
	case 0:
		return "%x0", nil
	case 1:
		return "%x1", nil
	case 2:
		return "%x2", nil
	case 3:
		return "%x3", nil
	case 4:
		return "%x4", nil
	case 5:
		return "%x5", nil
	default:
		return "", ErrUnsupportedFuncParamIndex
	}
}

func (*registersArm64) GetFuncReturnRegister() string {
	return "%x0"
}

// registers386 is the registersResolver implementation for 386 architecture
type registers386 struct{}

func (*registers386) GetFuncParamRegister(index int) (string, error) {
	switch index {
	case 0:
		return "%ax", nil
	case 1:
		return "%dx", nil
	case 2:
		return "%cx", nil
	case 3:
		return "$stack1", nil
	case 4:
		return "$stack2", nil
	case 5:
		return "$stack3", nil
	default:
		return "", ErrUnsupportedFuncParamIndex
	}
}

func (*registers386) GetFuncReturnRegister() string {
	return "%ax"
}
