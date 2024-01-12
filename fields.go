package tkbtf

import (
	"errors"
	"fmt"
	"strconv"
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
	if err = buildFieldsRecursive(spec, baseBtfType, 0, fieldsToBuild); err != nil {
		return err
	}

	return nil
}

func getArrayTypeSizeBytes(btfType btf.Type) uint32 {
	switch t := btfType.(type) {
	case *btf.Union:
		return t.Size
	case *btf.Struct:
		return t.Size
	case *btf.Int:
		return t.Size
	case *btf.Float:
		return t.Size
	case *btf.Enum:
		return t.Size
	case *btf.Datasec:
		return t.Size
	case *btf.Pointer:
		return 8
	case *btf.Typedef:
		return getArrayTypeSizeBytes(t.Type)
	case *btf.Const:
		return getArrayTypeSizeBytes(t.Type)
	default:
		return 0
	}
}

// buildFieldsRecursive recursively builds fields based on the parent type and fields slice.
// It returns ErrFieldNotFound if any field is not found.
func buildFieldsRecursive(spec btfSpec, parent btf.Type, parentOffsetBytes uint32, fields []*field) error {

	// If there are no fields left, return nil.
	if len(fields) == 0 {
		return nil
	}

	fieldName := fields[0].name

	// Get the members based on the type of the parent.
	var targetType btf.Type
	var targetOffsetBytes uint32
	switch t := parent.(type) {
	case *btf.Struct:
		for _, m := range t.Members {
			if m.Name != fieldName {
				continue
			}

			targetType = m.Type
			targetOffsetBytes = m.Offset.Bytes()
			break
		}
	case *btf.Union:
		for _, m := range t.Members {
			if m.Name != fieldName {
				continue
			}

			targetType = m.Type
			targetOffsetBytes = m.Offset.Bytes()
			break
		}
	case *btf.Array:
		arrayIndex := uint64(0)
		switch {
		case strings.HasPrefix(fieldName, "enum:"):
			enumTokens := strings.Split(fieldName, ":")
			if len(enumTokens) != 3 {
				return fmt.Errorf("index from enum invalid format: %w", ErrArrayIndexInvalidField)
			}

			enumName := enumTokens[1]
			enumValueName := enumTokens[2]

			var btfEnum *btf.Enum
			if err := spec.TypeByName(enumName, &btfEnum); err != nil {
				return err
			}

			found := false
			for _, enumValue := range btfEnum.Values {
				if enumValue.Name != enumValueName {
					continue
				}

				arrayIndex = enumValue.Value
				found = true
				break
			}

			if !found {
				return fmt.Errorf("index from enum not found: %w", ErrArrayIndexInvalidField)
			}
		case strings.HasPrefix(fieldName, "index:"):
			indexTokens := strings.Split(fieldName, ":")
			if len(indexTokens) != 2 {
				return fmt.Errorf("index invalid format: %w", ErrArrayIndexInvalidField)
			}
			var err error
			arrayIndex, err = strconv.ParseUint(indexTokens[1], 10, 32)
			if err != nil {
				return fmt.Errorf("index invalid unsigned int: %w", ErrArrayIndexInvalidField)
			}
		default:
			return fmt.Errorf("unknown type of index field: %w", ErrArrayIndexInvalidField)
		}

		if uint32(arrayIndex) >= t.Nelems {
			return fmt.Errorf("index bigger than array size: %w", ErrArrayIndexInvalidField)
		}

		targetType = t.Type
		targetOffsetBytes = getArrayTypeSizeBytes(targetType) * uint32(arrayIndex)

	case *btf.Pointer:
		// if the parent type is a ptr proceed by passing its target but make the offset 0
		// since we are entering a new ptr
		return buildFieldsRecursive(spec, t.Target, 0, fields)
	case *btf.Const:
		return buildFieldsRecursive(spec, t.Type, parentOffsetBytes, fields)
	}

	// If the member type is nil, return an error.
	if targetType == nil {
		return fmt.Errorf("getting field %s of type %s failed: %w", fieldName, parent.TypeName(), ErrFieldNotFound)
	}

	// Handle different types of member types.
	switch t := targetType.(type) {
	case *btf.Pointer:
		fields[0].offset = parentOffsetBytes + targetOffsetBytes
		fields[0].seen = true
		fields[0].includeInOffset = true
		fields[0].btfType = t.Target
		fields[0].parentBtfType = parent
		// if the member type is a ptr proceed by passing its target but make the offset 0
		// since we are entering a new ptr
		return buildFieldsRecursive(spec, t.Target, 0, fields[1:])
	case *btf.Array, *btf.Struct, *btf.Union, *btf.Const:
		fields[0].seen = true
		fields[0].includeInOffset = false
		fields[0].btfType = t
		fields[0].parentBtfType = parent
		return buildFieldsRecursive(spec, targetType, parentOffsetBytes+targetOffsetBytes, fields[1:])
	default:
		fields[0].offset = parentOffsetBytes + targetOffsetBytes
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
