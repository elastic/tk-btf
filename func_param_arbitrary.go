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

func (p *funcParamArbitrary) getParamIndex() int {
	return p.index
}
