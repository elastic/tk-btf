package tkbtf

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
)

// funcParamWithName is the implementation of the fieldsBuilder interface for constructing function parameter
// that matches the given name and a type that derives from the func prototype inside the btf spec.
type funcParamWithName struct {
	foundIndex int
	name       string
	fields     []*field
}

func (p *funcParamWithName) build(_ btfSpec, probeType ProbeType, funcType *btf.Func, regs registersResolver) (string, error) {
	var arg btf.FuncParam

	// funcParamWithName is compatible only with ProbeTypeKProbe
	if probeType != ProbeTypeKProbe {
		return "", ErrIncompatibleFetchArg
	}

	funcProtoType, ok := funcType.Type.(*btf.FuncProto)
	if !ok {
		return "", fmt.Errorf("btf func type is not a func proto %w", ErrFuncParamNotFound)
	}

	// Iterate through the function parameters to find the fieldsBuilder with the specified name
	for i, funcParam := range funcProtoType.Params {
		if funcParam.Name != p.name {
			continue
		}

		p.foundIndex = i
		arg = funcParam
		break
	}

	// if the fieldsBuilder type is not found, return an error
	if arg.Type == nil {
		return "", fmt.Errorf("getting func fieldsBuilder failed: %w", ErrFuncParamNotFound)
	}

	// build fields recursively
	if err := buildFieldsRecursive(arg.Type, 0, p.fields); err != nil {
		return "", err
	}

	// Build the tracing string for the fieldsBuilder
	return buildTracingEventFromFields(probeType, p.foundIndex, p.fields, regs)
}

func (p *funcParamWithName) getFields() []*field {
	return p.fields
}

func (p *funcParamWithName) getWrap() Wrap {
	return WrapNone
}
