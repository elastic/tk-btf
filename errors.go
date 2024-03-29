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
	// Currently, arm64, and amd64 are supported.
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
	// ErrArrayIndexInvalidField means that the field specified as an array index is invalid.
	ErrArrayIndexInvalidField = errors.New("array index invalid field")
)
