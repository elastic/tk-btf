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
