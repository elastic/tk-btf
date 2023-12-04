package tkbtf

import (
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
		return "", ErrFuncParamNotFound
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
