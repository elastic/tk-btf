package tkbtf

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/mock"
)

type mockedBTFSpec struct {
	mock.Mock
}

func generateBTFSpec() *Spec {

	btfTypesMap := make(map[string]btf.Type)

	typeInt8 := &btf.Int{
		Name:     "int8",
		Size:     1,
		Encoding: 0,
	}
	btfTypesMap["int8"] = typeInt8

	typeInt16 := &btf.Int{
		Name:     "int16",
		Size:     2,
		Encoding: 0,
	}
	btfTypesMap["int16"] = typeInt16

	typeInt32 := &btf.Int{
		Name:     "int",
		Size:     8,
		Encoding: 0,
	}
	btfTypesMap["int32"] = typeInt32

	iNode := &btf.Struct{
		Name: "inode",
		Size: 648,
		Members: []btf.Member{
			{
				Name:         "i_mode",
				Type:         typeInt16,
				Offset:       0,
				BitfieldSize: 0,
			},
			{
				Name:         "i_ino",
				Type:         typeInt32,
				Offset:       512,
				BitfieldSize: 0,
			},
		},
	}
	btfTypesMap["inode"] = iNode

	qstrStruct := &btf.Struct{
		Name: "qstr",
		Size: 16,
		Members: []btf.Member{
			{
				Name: "name",
				Type: &btf.Pointer{
					Target: &btf.Const{
						Type: typeInt8,
					},
				},
				Offset:       64,
				BitfieldSize: 0,
			},
		},
	}
	btfTypesMap["qstr"] = qstrStruct

	dEntry := &btf.Struct{
		Name: "dentry",
		Size: 192,
		Members: []btf.Member{
			{
				Name:         "d_name",
				Type:         qstrStruct,
				Offset:       256,
				BitfieldSize: 0,
			},
			{
				Name: "d_inode",
				Type: &btf.Pointer{
					Target: iNode,
				},
				Offset:       384,
				BitfieldSize: 0,
			},
		},
	}
	btfTypesMap["dentry"] = dEntry

	functionTypeProto := &btf.FuncProto{
		Return: typeInt16,
		Params: []btf.FuncParam{
			{
				Name: "dentry_param",
				Type: &btf.Pointer{
					Target: dEntry,
				},
			},
			{
				Name: "inode_param",
				Type: &btf.Pointer{
					Target: iNode,
				},
			},
		},
	}
	btfTypesMap["test_function_proto"] = functionTypeProto

	functionType := &btf.Func{
		Name:    "test_function",
		Type:    functionTypeProto,
		Linkage: 0,
	}
	btfTypesMap["test_function"] = functionType

	functionWithRetProto := &btf.FuncProto{
		Return: &btf.Pointer{
			Target: dEntry,
		},
		Params: []btf.FuncParam{
			{
				Name: "dentry_param",
				Type: &btf.Pointer{
					Target: dEntry,
				},
			},
			{
				Name: "inode_param",
				Type: &btf.Pointer{
					Target: iNode,
				},
			},
		},
	}
	btfTypesMap["test_function_with_ret_proto"] = functionWithRetProto

	functionWithRetType := &btf.Func{
		Name:    "test_function_with_ret",
		Type:    functionWithRetProto,
		Linkage: 0,
	}
	btfTypesMap["test_function_with_ret"] = functionWithRetType

	return &Spec{
		spec: newMockedBTFSpecWithTypesMap(btfTypesMap),
		regs: &registersAmd64{},
	}
}

func mockAnyTypesByNameOnAnything(returnArguments ...interface{}) *mockedBTFSpec {
	m := new(mockedBTFSpec)
	m.On("AnyTypesByName", mock.Anything).Return(returnArguments...)
	return m
}

func (m *mockedBTFSpec) TypeByName(name string, typ interface{}) error {
	args := m.Called(name, typ)
	return args.Error(0)
}

func (m *mockedBTFSpec) AnyTypesByName(name string) ([]btf.Type, error) {
	args := m.Called(name)
	return args.Get(0).([]btf.Type), args.Error(1)
}

func (m *mockedBTFSpec) copy() btfSpec {
	args := m.Called()
	return args.Get(0).(btfSpec)
}

func (m *mockedBTFSpec) typeID(_ btf.Type) (btf.TypeID, error) {
	args := m.Called()
	return args.Get(0).(btf.TypeID), args.Error(1)
}

type mockedBTFSpecWithTypesMap struct {
	Types map[string]btf.Type
	Ids   map[btf.Type]btf.TypeID
}

func newMockedBTFSpecWithTypesMap(mapTypes map[string]btf.Type) btfSpec {
	mockedSpec := &mockedBTFSpecWithTypesMap{
		Types: mapTypes,
		Ids:   make(map[btf.Type]btf.TypeID),
	}

	counter := 0
	for _, typ := range mapTypes {
		mockedSpec.Ids[typ] = btf.TypeID(counter)
		counter++
	}

	return mockedSpec
}

func (m *mockedBTFSpecWithTypesMap) typeID(t btf.Type) (btf.TypeID, error) {
	typId, exists := m.Ids[t]
	if exists {
		return typId, nil
	}

	return 0, errors.New("type not found")
}

func (m *mockedBTFSpecWithTypesMap) TypeByName(name string, typ interface{}) error {
	storedBTFType, exists := m.Types[name]
	if !exists {
		return errors.New("not found")
	}

	typeInterface := reflect.TypeOf((*btf.Type)(nil)).Elem()

	// typ may be **T or *Type
	typValue := reflect.ValueOf(typ)
	if typValue.Kind() != reflect.Ptr {
		return fmt.Errorf("%T is not a pointer", typ)
	}

	typPtr := typValue.Elem()
	if !typPtr.CanSet() {
		return fmt.Errorf("%T cannot be set", typ)
	}

	wanted := typPtr.Type()
	if wanted == typeInterface {
		// This is *Type. Unwrap the value's type.
		wanted = typPtr.Elem().Type()
	}

	if !wanted.AssignableTo(typeInterface) {
		return fmt.Errorf("%T does not satisfy Type interface", typ)
	}

	if !reflect.TypeOf(storedBTFType).AssignableTo(wanted) {
		return fmt.Errorf("%T cannot be assigned by %T", typ, storedBTFType)
	}

	typPtr.Set(reflect.ValueOf(storedBTFType))

	return nil
}

func (m *mockedBTFSpecWithTypesMap) copy() btfSpec {
	typesCopy := make(map[string]btf.Type)
	for k, v := range m.Types {
		typesCopy[k] = v
	}

	return &mockedBTFSpecWithTypesMap{Types: typesCopy}
}

func (m *mockedBTFSpecWithTypesMap) AnyTypesByName(name string) ([]btf.Type, error) {
	t, exists := m.Types[name]
	if !exists {
		return nil, errors.New("not found")
	}

	return []btf.Type{t}, nil
}
