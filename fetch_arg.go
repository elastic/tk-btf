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
	"errors"
	"strings"

	"github.com/cilium/ebpf/btf"
)

// Wrap indicates if and how the first field should be wrapped in fieldsBuilder that process the fields
// without relying on the existence of the function prototype in the BTF spec, namely FuncParamWithCustomType,
// FuncParamArbitrary and FuncReturnArbitrary.
type Wrap uint32

const (
	// WrapNone there is no wrapping to the type.
	WrapNone Wrap = iota
	// WrapPointer the type will be wrapped under a pointer that targets to it.
	WrapPointer
	// WrapStructPointer the type will be wrapped as a member of an arbitrary struct at offset zero which is wrapped
	// under a pointer.
	WrapStructPointer
)

// fieldsBuilder is an interface that abstracts all the different types of fieldsBuilder.
type fieldsBuilder interface {
	// build processes the fields.
	build(spec btfSpec, probeType ProbeType, funcType *btf.Func, regs registersResolver) (string, error)
	// getFields returns a slice of the fields.
	getFields() []*field
	// getWrap returns the wrap used.
	getWrap() Wrap
}

type fetchArg struct {
	name              string
	argType           string
	fBuilders         []fieldsBuilder
	btfFunc           *btf.Func
	successfulBuilder fieldsBuilder
}

// NewFetchArg creates and returns a new fetchArg with the given name and type. Note that
// fetchArg requires fieldsBuilders to be attached to it which is done by the functions
// FuncParamWithName, FuncParamArbitrary, and FuncParamWithCustomType for KProbes. Respectively,
// for KRetProbes the fieldsBuilder functions are FuncReturn and FuncReturnArbitrary.
// When a fetch arg is built without any fieldsBuilder attached, ErrMissingFieldBuilders is returned.
// Also, that you can add multiple fieldsBuilders to the same fetchArg but the first one, in respect
// to the order they were added, that is built without an error will satisfy the fetchArg.
func NewFetchArg(argName string, argType string) *fetchArg {
	return &fetchArg{
		name:      argName,
		argType:   argType,
		fBuilders: nil,
	}
}

// FuncParamWithName attaches a fieldsBuilder to the fetchArg that does require the function prototype
// to be available in the BTF spec. Based on it, it extracts the parameter index and type that matches the given name
// and then builds the fields as members of the former.
//
// Note that FuncParamWithName is compatible
// only with ProbeTypeKProbe. If combined with any other type of Probe it will return an ErrIncompatibleFetchArg
// error.
func (f *fetchArg) FuncParamWithName(paramName string, fields ...string) *fetchArg {
	f.fBuilders = append(f.fBuilders, &funcParamWithName{
		foundIndex: -1,
		name:       paramName,
		fields:     paramFieldsFromNames(fields...),
	})
	return f
}

// FuncParamArbitrary attaches a fieldsBuilder to the fetchArg that doesn't require the function prototype
// to be available in the BTF spec. Instead, it utilises the given arbitrary parameter index to calculate
// the respective architecture register, and it uses the first supplied field to determine the type of this
// arbitrary parameter. Then it processes the remaining fields as members of the former. When more arbitrary
// conversions are needed the caller can utilise different Wrap kinds to achieve them. This is kind of
// fieldsBuilder is useful when the function prototype is not available in the BTF spec but still we take advantage
// of calculating the fields offsets based on the types in the BTF spec.
//
// Note that FuncParamArbitrary is compatible only with ProbeTypeKProbe. If combined with any other type of Probe
// it will return an ErrIncompatibleFetchArg error.
func (f *fetchArg) FuncParamArbitrary(paramIndex int, wrap Wrap, fields ...string) *fetchArg {
	f.fBuilders = append(f.fBuilders, &funcParamAtIndex{
		index:  paramIndex,
		fields: paramFieldsFromNames(fields...),
		wrap:   wrap,
	})
	return f
}

// FuncParamWithCustomType attaches a fieldsBuilder to the fetchArg that does require the function prototype
// to be available in the BTF spec. Based on it, it extracts the parameter index that matches the given name
// but it uses the first supplied field as the type of the parameter. Then it processes the remaining fields
// as members of the former. This kind of fieldsBuilder is useful when the type of the function parameter is
// of type (*void). When more advanced conversions are needed the caller can utilise different Wrap kinds to
// achieve them.
//
// Note that FuncParamWithCustomType is compatible only with ProbeTypeKProbe. If combined with any other type
// of Probe it will return an ErrIncompatibleFetchArg error.
func (f *fetchArg) FuncParamWithCustomType(paramName string, wrap Wrap, fields ...string) *fetchArg {
	f.fBuilders = append(f.fBuilders, &funcParamArbitrary{
		name: paramName,
		funcParamAtIndex: funcParamAtIndex{
			fields: paramFieldsFromNames(fields...),
			wrap:   wrap,
		},
	})
	return f
}

// FuncReturn attaches a fieldsBuilder to the fetchArg that does require the function prototype
// to be available in the BTF spec. Based on it, it extracts the return value of the function
// builds the fields as members of the former.
//
// Note that FuncReturn is compatible only with ProbeTypeKRetProbe. If combined with any other type
// of Probe it will return an ErrIncompatibleFetchArg error.
func (f *fetchArg) FuncReturn(fields ...string) *fetchArg {
	f.fBuilders = append(f.fBuilders, &funcReturn{
		fields: paramFieldsFromNames(fields...),
	})
	return f
}

// FuncReturnArbitrary attaches a fieldsBuilder to the fetchArg that doesn't require the function prototype
// to be available in the BTF spec. Instead, it utilises the first supplied field as the type of the function
// return value. Then it processes the remaining fields as members of the former. When more arbitrary
// conversions are needed the caller can utilise different Wrap kinds to achieve them. This is kind of
// fieldsBuilder is useful when the function prototype is not available in the BTF spec but still we take advantage
// of calculating the fields offsets based on the types in the BTF spec.
//
// Note that FuncReturnArbitrary is compatible only with ProbeTypeKRetProbe. If combined with any other type of
// Probe it will return an ErrIncompatibleFetchArg error.
func (f *fetchArg) FuncReturnArbitrary(wrap Wrap, fields ...string) *fetchArg {
	f.fBuilders = append(f.fBuilders, &funcReturnArbitrary{
		wrap:   wrap,
		fields: paramFieldsFromNames(fields...),
	})
	return f
}

// build iterates all attached fieldBuilders to the fetchArg until the first that builds successfully. Then based on it,
// it builds the respective tracing fs representation of the fetchArg. If there are no attached fieldBuilders it returns
// an ErrMissingFieldBuilders error. If no builder builds successfully it returns all the errors that occurred during
// build.
func (f *fetchArg) build(spec btfSpec, probeType ProbeType, funcType *btf.Func, regs registersResolver) (string, error) {
	var allErr error

	// missing fieldBuilders
	if len(f.fBuilders) == 0 {
		return "", ErrMissingFieldBuilders
	}

	f.btfFunc = funcType

	// iterate all attached fieldBuilders
	for _, p := range f.fBuilders {
		paramTracingStr, err := p.build(spec, probeType, funcType, regs)
		if err != nil {
			// in case of error continue to the next fieldsBuilder
			allErr = errors.Join(allErr, err)
			continue
		}

		f.successfulBuilder = p

		fetchArgTracingStr := strings.Builder{}
		fetchArgTracingStr.WriteString(f.name)
		fetchArgTracingStr.WriteString("=")
		if f.argType == "string" {
			fetchArgTracingStr.WriteString("+0(")
			fetchArgTracingStr.WriteString(paramTracingStr)
			fetchArgTracingStr.WriteString("):string")
		} else {
			fetchArgTracingStr.WriteString(paramTracingStr)
			fetchArgTracingStr.WriteString(":")
			fetchArgTracingStr.WriteString(f.argType)
		}

		return fetchArgTracingStr.String(), nil
	}

	return "", allErr
}
