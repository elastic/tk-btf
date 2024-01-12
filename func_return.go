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

// funcReturn is the implementation of the fieldsBuilder interface for constructing function return relying
// on the function prototype inside the btf spec.
type funcReturn struct {
	fields []*field
}

// build
func (p *funcReturn) build(_ btfSpec, probeType ProbeType, funcType *btf.Func, regs registersResolver) (string, error) {

	// funcReturn is compatible only with ProbeTypeKRetProbe
	if probeType != ProbeTypeKRetProbe {
		return "", ErrIncompatibleFetchArg
	}

	// function prototype is required
	funcProtoType, ok := funcType.Type.(*btf.FuncProto)
	if !ok {
		return "", fmt.Errorf("btf func type is not a func proto %w", ErrFuncParamNotFound)
	}

	// If there are fields defined for the fieldsBuilder, build them recursively
	if err := buildFieldsRecursive(funcProtoType.Return, 0, p.fields); err != nil {
		return "", err
	}

	// Build the tracing string for the fieldsBuilder
	return buildTracingEventFromFields(probeType, 0, p.fields, regs)
}

func (p *funcReturn) getFields() []*field {
	return p.fields
}

func (p *funcReturn) getWrap() Wrap {
	return WrapNone
}
