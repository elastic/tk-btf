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

	"github.com/cilium/ebpf/btf"
)

// funcParamArbitrary is the implementation of the fieldsBuilder interface for constructing function parameter
// that matches the given name from the function prototype inside the btf spec and type that derives from the
// first supplied field.
type funcParamArbitrary struct {
	name string
	funcParamAtIndex
}

func (p *funcParamArbitrary) build(spec btfSpec, probeType ProbeType, funcType *btf.Func, regs registersResolver) (string, error) {
	var arg btf.FuncParam

	// funcParamArbitrary is compatible only with ProbeTypeKProbe
	if probeType != ProbeTypeKProbe {
		return "", ErrIncompatibleFetchArg
	}

	// function prototype is required
	funcProtoType, ok := funcType.Type.(*btf.FuncProto)
	if !ok {
		return "", fmt.Errorf("btf func type is not a func proto %w", ErrFuncParamNotFound)
	}

	// find the function parameter with the given name.
	for i, funcParam := range funcProtoType.Params {
		if funcParam.Name != p.name {
			continue
		}

		p.index = i
		arg = funcParam
		break
	}

	// if the function parameter is not found, return an error.
	if arg.Type == nil {
		return "", fmt.Errorf("getting func fieldsBuilder failed: %w", ErrFuncParamNotFound)
	}

	// Build the fieldsBuilder at the given foundIndex.
	return p.funcParamAtIndex.build(spec, probeType, funcType, regs)
}

func (p *funcParamArbitrary) getFields() []*field {
	return p.fields
}

func (p *funcParamArbitrary) getWrap() Wrap {
	return p.wrap
}
