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
	"github.com/cilium/ebpf/btf"
)

// funcParamAtIndex is the implementation of the fieldsBuilder interface for constructing function
// parameter with an arbitrary index and type that derives from the first supplied field.
type funcParamAtIndex struct {
	index  int
	fields []*field
	wrap   Wrap
}

func (p *funcParamAtIndex) build(spec btfSpec, probeType ProbeType, _ *btf.Func, regs registersResolver) (string, error) {
	// funcParamAtIndex is compatible only with ProbeTypeKProbe
	if probeType != ProbeTypeKProbe {
		return "", ErrIncompatibleFetchArg
	}

	if err := buildFieldsWithWrap(spec, p.wrap, p.fields); err != nil {
		return "", err
	}

	// Build the tracing string for the fieldsBuilder
	return buildTracingEventFromFields(probeType, p.index, p.fields, regs)
}

func (p *funcParamAtIndex) getFields() []*field {
	return p.fields
}

func (p *funcParamAtIndex) getWrap() Wrap {
	return p.wrap
}
