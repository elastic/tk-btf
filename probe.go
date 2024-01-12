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
	"strings"
)

// ProbeType highlights the type of the Probe.
// (https://docs.kernel.org/trace/kprobetrace.html#synopsis-of-kprobe-events)
type ProbeType uint32

const (
	// ProbeTypeKProbe captures a KProbe.
	ProbeTypeKProbe ProbeType = iota
	// ProbeTypeKRetProbe captures a KRetProbe.
	ProbeTypeKRetProbe
)

type Probe struct {
	ref        string
	symbolName string
	probeType  ProbeType

	duplicateFetchArgs bool

	fetchArgOrderName []string
	fetchArgs         map[string]*fetchArg

	tracingEventProbe  string
	tracingEventFilter string
}

// NewKProbe creates and returns new Probe of type ProbeTypeKProbe.
func NewKProbe() *Probe {
	return &Probe{
		probeType: ProbeTypeKProbe,
		fetchArgs: make(map[string]*fetchArg),
	}
}

// NewKRetProbe creates and returns new Probe of type ProbeTypeKRetProbe.
func NewKRetProbe() *Probe {
	return &Probe{
		probeType: ProbeTypeKRetProbe,
		fetchArgs: make(map[string]*fetchArg),
	}
}

// AddFetchArgs attaches the given fetchArgs to the Probe.
func (p *Probe) AddFetchArgs(args ...*fetchArg) *Probe {
	// Iterate over the given fetchArgs
	for _, a := range args {
		// Check if the fetchArg already exists in the fetchArgs map
		if _, exists := p.fetchArgs[a.name]; !exists {
			// If it doesn't exist, add the fetchArg name to the fetchArgOrderName slice
			p.fetchArgOrderName = append(p.fetchArgOrderName, a.name)
		} else {
			p.duplicateFetchArgs = true
		}

		// Add the fetchArg to the fetchArgs map
		p.fetchArgs[a.name] = a
	}

	return p
}

// SetRef sets the reference name of the probe. This is useful when multiple probes are attached to the same symbol
// and an extra factor of distinguishing them is required.
func (p *Probe) SetRef(ref string) *Probe {
	p.ref = ref
	return p
}

// SetFilter sets a tracing event filter to the probe.
// It takes a filter string as input and returns a pointer to the probe.
// Note that this doesn't validate the supplied filter string and it up
// to the caller to check its validity.
func (p *Probe) SetFilter(filter string) *Probe {
	p.tracingEventFilter = filter
	return p
}

// GetSymbolName returns the symbol name of the Probe.
func (p *Probe) GetSymbolName() string {
	return p.symbolName
}

// GetTracingEventProbe returns the tracing event probe string for the Probe.
func (p *Probe) GetTracingEventProbe() string {
	return p.tracingEventProbe
}

// GetTracingEventFilter returns the tracing event filter of the Probe.
// It returns an empty string if no filter is set.
func (p *Probe) GetTracingEventFilter() string {
	return p.tracingEventFilter
}

// GetType returns the ProbeType.
func (p *Probe) GetType() ProbeType {
	return p.probeType
}

// GetID returns the ID of the Probe. The ID is the result of combining the probe
// type and the symbol name or the reference name if it is set.
func (p *Probe) GetID() string {
	var id strings.Builder

	switch p.probeType {
	case ProbeTypeKProbe:
		id.WriteString("kprobe_")
	case ProbeTypeKRetProbe:
		id.WriteString("kretprobe_")
	}

	switch {
	case p.ref == "":
		id.WriteString(p.symbolName)
	default:
		id.WriteString(p.ref)
	}

	return id.String()
}

// build updates the Probe with the provided symbol name and builds one by one the attached fetchArgs, respecting
// the order they were attached. It returns any error encountered during the build process.
func (p *Probe) build(symbolName string, spec btfSpec, funcType *btf.Func, regs registersResolver) error {
	var probeTracing strings.Builder

	if p.duplicateFetchArgs {
		return ErrDuplicateFetchArgs
	}

	p.symbolName = symbolName
	p.tracingEventProbe = ""

	// Iterate over the fetch args with the order they were added
	for _, argName := range p.fetchArgOrderName {
		arg, ok := p.fetchArgs[argName]
		if !ok {
			continue
		}

		// Build the fetch argument
		fetchArgTracingStr, err := arg.build(spec, p.probeType, funcType, regs)
		if err != nil {
			return err
		}

		if fetchArgTracingStr == "" {
			return fmt.Errorf("fetch arg %s returned empty tracing event probe string", argName)
		}

		// string builder is not empty (contains already a fetch arg) thus add space separator
		if probeTracing.Len() > 0 {
			probeTracing.WriteString(" ")
		}
		probeTracing.WriteString(fetchArgTracingStr)
	}

	p.tracingEventProbe = probeTracing.String()

	return nil
}
