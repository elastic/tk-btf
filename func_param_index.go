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
