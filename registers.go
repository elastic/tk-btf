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
