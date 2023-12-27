package tkbtf

import "errors"

var (
	// ErrSpecKernelNotSupported means that the running kernel does not support btf.
	ErrSpecKernelNotSupported = errors.New("running kernel does not support btf")
	// ErrSymbolNotFound means that the symbol (aka function name) was not found in the BTF spec.
	ErrSymbolNotFound = errors.New("symbol not found in btf spec")
	// ErrFuncParamNotFound means that the function parameter was not found in the btf func proto.
	ErrFuncParamNotFound = errors.New("function parameter not found")
	// ErrFieldNotFound means that a field is not part of the parent btf type members.
	ErrFieldNotFound = errors.New("field not found")
	// ErrUnsupportedFuncParamIndex means that the parameter index could not be mapped to any register.
	ErrUnsupportedFuncParamIndex = errors.New("unsupported func parameter index")
	// ErrUnsupportedArch means that the architecture is not supported.
	// Currently, arm64, amd64, 386 are supported.
	ErrUnsupportedArch = errors.New("unsupported architecture")
	// ErrIncompatibleFetchArg means that a fetch arg is assigned to probe type that is not compatible with,
	// e.g. FuncParamArbitrary is not compatible with ProbeTypeKRetProbe.
	ErrIncompatibleFetchArg = errors.New("incompatible fetch arg with probe type")
	// ErrMissingFieldBuilders means that the fetch args has not any field builders assigned.
	ErrMissingFieldBuilders = errors.New("missing field builders from fetch arg")
	// ErrMissingFields means that the fetch arg of a type that requires fields has not any fields assigned.
	ErrMissingFields = errors.New("missing fields")
	// ErrDuplicateFetchArgs means that two or more fetch args with the same name are specified.
	ErrDuplicateFetchArgs = errors.New("duplicate fetch args")
	// ErrMissingSymbolNames means that no symbol names are specified.
	ErrMissingSymbolNames = errors.New("missing symbol names")
	// ErrUnsupportedWrapType means that the wrap type is not supported.
	ErrUnsupportedWrapType = errors.New("unsupported wrap type")
)
