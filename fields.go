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
	"fmt"
	"strings"

	"github.com/cilium/ebpf/btf"
)

type field struct {
	name            string
	offset          uint32
	seen            bool
	includeInOffset bool
	parentBtfType   btf.Type
	btfType         btf.Type
}

// paramFieldsFromNames initializes and returns a slice of field pointers based on the provided field names.
// Each field pointer is initialized with default values.
func paramFieldsFromNames(fields ...string) []*field {
	fieldsSlice := make([]*field, len(fields))

	for idx, fieldName := range fields {
		fieldsSlice[idx] = &field{
			name: fieldName,
		}
	}

	return fieldsSlice
}

// buildFieldsWithWrap builds the fields with the provided wrap.
func buildFieldsWithWrap(spec btfSpec, wrap Wrap, fields []*field) error {

	if len(fields) == 0 {
		return ErrMissingFields
	}

	// when we build fields with wrap the first field always points to the target type
	paramTypeToSearch := fields[0]

	// Search for the BTF types with the specified name
	btfTypes, err := spec.AnyTypesByName(paramTypeToSearch.name)
	if err != nil {
		return errors.Join(ErrFieldNotFound, err)
	}

	var btfTarget btf.Type

	// Check the number of BTF types found
	switch len(btfTypes) {
	case 0:
		return fmt.Errorf("getting func fieldsBuilder %s failed: %w", paramTypeToSearch.name, ErrFuncParamNotFound)
	case 1:
		btfTarget = btfTypes[0]
	default:
		// If we found multiple types, prioritize struct ones
		for _, btfType := range btfTypes {
			if btfTarget != nil {
				break
			}
			switch t := btfType.(type) {
			case *btf.Struct:
				btfTarget = t
			}
		}

		// If no struct type found, use the first type in the list
		if btfTarget == nil {
			btfTarget = btfTypes[0]
		}
	}

	var fieldsToBuild []*field
	var baseBtfType btf.Type

	switch wrap {
	case WrapNone:
		// No wrapping, just feed the fieldsBuilder down
		fieldsToBuild = fields[1:]
		baseBtfType = btfTarget
	case WrapPointer:
		// Wrap the target type in a pointer
		fieldsToBuild = fields[1:]
		customPtr := &btf.Pointer{
			Target: btfTarget,
		}
		baseBtfType = customPtr
	case WrapStructPointer:
		// Wrap the target type in an artificial struct pointer
		// at offset 0
		fieldsToBuild = fields
		customPtr := &btf.Pointer{
			Target: btfTarget,
		}

		customStruct := &btf.Struct{
			Name: "__custom_struct",
			Size: 8,
			Members: []btf.Member{
				{
					Name:         paramTypeToSearch.name,
					Type:         customPtr,
					Offset:       0,
					BitfieldSize: 0,
				},
			},
		}
		baseBtfType = customStruct
	default:
		return ErrUnsupportedWrapType
	}

	// Update the paramTypeToSearch struct with the BTF type information
	paramTypeToSearch.seen = true
	paramTypeToSearch.includeInOffset = false
	paramTypeToSearch.btfType = baseBtfType

	// Build the BTF representation of the fields recursively
	if err = buildFieldsRecursive(baseBtfType, 0, fieldsToBuild); err != nil {
		return err
	}

	return nil
}

// buildFieldsRecursive recursively builds fields based on the parent type and fields slice.
// It returns ErrFieldNotFound if any field is not found.
func buildFieldsRecursive(parent btf.Type, parentOffset btf.Bits, fields []*field) error {

	// If there are no fields left, return nil.
	if len(fields) == 0 {
		return nil
	}

	// Get the members based on the type of the parent.
	var members []btf.Member
	switch t := parent.(type) {
	case *btf.Struct:
		members = t.Members
	case *btf.Union:
		members = t.Members
	case *btf.Pointer:
		// if the parent type is a ptr proceed by passing its target but make the offset 0
		// since we are entering a new ptr
		return buildFieldsRecursive(t.Target, 0, fields)
	case *btf.Const:
		return buildFieldsRecursive(t.Type, parentOffset, fields)
	}

	// Get the name of the first field.
	memberName := fields[0].name

	// Find the member with the matching name.
	var member btf.Member
	for _, m := range members {
		if m.Name != memberName {
			continue
		}

		member = m
		break
	}

	// If the member type is nil, return an error.
	if member.Type == nil {
		return fmt.Errorf("getting field %s of type %s failed: %w", memberName, parent.TypeName(), ErrFieldNotFound)
	}

	// Handle different types of member types.
	switch t := member.Type.(type) {
	case *btf.Pointer:
		fields[0].offset = (parentOffset + member.Offset).Bytes()
		fields[0].seen = true
		fields[0].includeInOffset = true
		fields[0].btfType = t.Target
		fields[0].parentBtfType = parent
		// if the member type is a ptr proceed by passing its target but make the offset 0
		// since we are entering a new ptr
		return buildFieldsRecursive(member.Type, 0, fields[1:])
	case *btf.Struct, *btf.Union, *btf.Const:
		fields[0].seen = true
		fields[0].includeInOffset = false
		fields[0].btfType = t
		fields[0].parentBtfType = parent
		return buildFieldsRecursive(member.Type, member.Offset, fields[1:])
	default:
		fields[0].offset = (parentOffset + member.Offset).Bytes()
		fields[0].seen = true
		fields[0].includeInOffset = true
		fields[0].btfType = t
		fields[0].parentBtfType = parent
		return nil
	}
}

// buildTracingEventFromFields generates, based on the fields, the respective trace fs offsets alongside the
// arch-specific register
func buildTracingEventFromFields(probeType ProbeType, paramIndex int, fields []*field, regs registersResolver) (string, error) {
	var (
		registerStr string
		err         error
		eventParam  strings.Builder
	)

	switch probeType {
	case ProbeTypeKRetProbe:
		registerStr = regs.GetFuncReturnRegister()
	case ProbeTypeKProbe:
		registerStr, err = regs.GetFuncParamRegister(paramIndex)
		if err != nil {
			return "", fmt.Errorf("getting register failed: %w", err)
		}
	}

	// the first field is the last offset in the string representation, so we need to loop in reverse
	offsetsCount := 0
	for i := len(fields) - 1; i >= 0; i-- {
		fld := fields[i]
		if !fld.seen {
			return "", fmt.Errorf("field %s not found: %w", fld.name, ErrFieldNotFound)
		}

		if !fld.includeInOffset {
			continue
		}

		eventParam.WriteString(fmt.Sprintf("+%d(", fld.offset))
		offsetsCount++
	}

	// write the register
	eventParam.WriteString(registerStr)

	// write all closing offset parentheses
	for i := 0; i < offsetsCount; i++ {
		eventParam.WriteString(")")
	}

	return eventParam.String(), nil
}
