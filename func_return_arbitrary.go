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

// funcReturnArbitrary is the implementation of the fieldsBuilder interface for constructing function return
// from the function prototype inside the btf spec and type that derives from the first supplied field.
type funcReturnArbitrary struct {
	wrap   Wrap
	fields []*field
}

func (p *funcReturnArbitrary) build(spec btfSpec, probeType ProbeType, _ *btf.Func, regs registersResolver) (string, error) {

	// funcReturn is compatible only with ProbeTypeKRetProbe
	if probeType != ProbeTypeKRetProbe {
		return "", ErrIncompatibleFetchArg
	}

	// If there are fields defined for the fieldsBuilder, build them recursively
	if err := buildFieldsWithWrap(spec, p.wrap, p.fields); err != nil {
		return "", err
	}

	// Build the tracing string for the fieldsBuilder
	return buildTracingEventFromFields(probeType, 0, p.fields, regs)
}

func (p *funcReturnArbitrary) getFields() []*field {
	return p.fields
}

func (p *funcReturnArbitrary) getWrap() Wrap {
	return p.wrap
}
