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
	"github.com/cilium/ebpf/btf"
)

type typeToStrip struct {
	typ          btf.Type
	fieldsToKeep map[string]struct{}
}

type typesToStripMap map[btf.TypeID]*typeToStrip

// addType adds a type to the typesToStripMap.
func (t typesToStripMap) addType(spec btfSpec, typ btf.Type) error {
	return t.addTypeField(spec, typ, "")
}

// addType adds a type to the typesToStripMap and a field to keep of that type.
func (t typesToStripMap) addTypeField(spec btfSpec, typ btf.Type, field string) error {
	switch tt := typ.(type) {
	case *btf.Pointer:
		return t.addTypeField(spec, tt.Target, field)
	case *btf.Const:
		return t.addTypeField(spec, tt.Type, field)
	case *btf.Typedef:
		return t.addTypeField(spec, tt.Type, field)
	}

	id, err := spec.typeID(typ)
	if err != nil {
		return err
	}

	if _, exists := t[id]; !exists {
		t[id] = &typeToStrip{
			typ:          typ,
			fieldsToKeep: make(map[string]struct{}),
		}
	}

	if field == "" {
		return nil
	}

	t[id].fieldsToKeep[field] = struct{}{}
	return nil
}

// checkTypeInMap checks if a type is in the typesToStripMap.
func (t typesToStripMap) checkTypeInMap(spec btfSpec, typ btf.Type) bool {
	switch tt := typ.(type) {
	case *btf.Pointer:
		return t.checkTypeInMap(spec, tt.Target)
	case *btf.Const:
		return t.checkTypeInMap(spec, tt.Type)
	case *btf.Typedef:
		return t.checkTypeInMap(spec, tt.Type)
	}

	id, err := spec.typeID(typ)
	if err != nil {
		return false
	}

	_, exists := t[id]
	return exists
}

// strip removes fields that are not in the typesToStripMap.
func (t typesToStripMap) strip(spec btfSpec) {
	for _, typ := range t {
		switch tt := typ.typ.(type) {
		case *btf.Struct:
			allMembers := tt.Members
			var newMembers []btf.Member

			for _, member := range allMembers {
				if _, exists := typ.fieldsToKeep[member.Name]; exists {
					newMembers = append(newMembers, member)
				}
			}

			tt.Members = newMembers
		case *btf.Union:
			allMembers := tt.Members
			var newMembers []btf.Member

			for _, member := range allMembers {
				if _, exists := typ.fieldsToKeep[member.Name]; exists {
					newMembers = append(newMembers, member)
				}
			}

			tt.Members = newMembers
		case *btf.FuncProto:
			allParams := tt.Params
			var newParams []btf.FuncParam

			for _, p := range allParams {
				if !t.checkTypeInMap(spec, p.Type) {
					// If the fieldsBuilder type is not in the map, replace it with a void type
					// to save space
					p.Type = &btf.Pointer{
						Target: &btf.Void{},
					}
					newParams = append(newParams, p)
				} else {
					newParams = append(newParams, p)
				}
			}

			tt.Params = newParams
			if !t.checkTypeInMap(spec, tt.Return) {
				// If the return type is not in the map, replace it with a void type
				// to save space
				tt.Return = &btf.Pointer{
					Target: &btf.Void{},
				}
			}
		}
	}
}
