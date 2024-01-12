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

// Symbol represents a function symbol and holds the list of probes associated with it.
type Symbol struct {
	names           []string
	probes          []*Probe
	foundSymbolName string
	skipValidation  bool
}

// NewSymbol creates and returns a new Symbol instance with the given symbol names.
func NewSymbol(symbolNames ...string) *Symbol {
	symbol := &Symbol{
		skipValidation: false,
	}

	for _, symbolName := range symbolNames {
		trimmedSymbolName := strings.TrimSpace(symbolName)
		if trimmedSymbolName != "" {
			symbol.names = append(symbol.names, trimmedSymbolName)
		}
	}

	return symbol
}

// NewSymbolWithoutValidation creates and returns a new Symbol instance
// which during build won't try to extract the function prototype from the btf spec.
// This is useful in case the function prototype is not available in the btf spec.
func NewSymbolWithoutValidation(symbolName string) *Symbol {
	symbol := &Symbol{
		// Set skipValidation field to true to indicate that no validation should be performed.
		skipValidation: true,
	}

	trimmedSymbolName := strings.TrimSpace(symbolName)
	if trimmedSymbolName != "" {
		symbol.names = append(symbol.names, trimmedSymbolName)
	}

	return symbol
}

// AddProbes attaches the given probes to the Symbol.
func (s *Symbol) AddProbes(p ...*Probe) *Symbol {
	s.probes = append(s.probes, p...)
	return s
}

// build is a method of the Symbol struct that builds the symbol using the provided btfSpec.
// It returns an error if any symbol is not found or if there is an error in building the symbol.
func (s *Symbol) build(spec btfSpec, regs registersResolver) error {
	var funcType *btf.Func

	if len(s.names) == 0 {
		return ErrMissingSymbolNames
	}

	// If skipValidation is false, validate each symbol until the first successfully validated
	if !s.skipValidation {
		var allErr error
		for _, symbolName := range s.names {
			err := spec.TypeByName(symbolName, &funcType)
			if err != nil {
				allErr = errors.Join(allErr, fmt.Errorf("getting func of %s failed: %w", symbolName, ErrSymbolNotFound))
				continue
			}
			break
		}

		if funcType == nil {
			return allErr
		}

		s.foundSymbolName = funcType.Name
	} else {
		s.foundSymbolName = s.names[0]
	}

	for _, p := range s.probes {
		if err := p.build(s.foundSymbolName, spec, funcType, regs); err != nil {
			return err
		}
	}

	return nil
}

// GetSymbolName returns the name of the resolved symbol. If the Symbol is set not to validate the symbol
// it returns the first symbol name of the provided ones during Symbol instantiation.
//
// Note if you call GetSymbolName on a Symbol that has not been built, it will return an empty string.
func (s *Symbol) GetSymbolName() string {
	return s.foundSymbolName
}

// GetProbes returns the list of probes attached to the Symbol.
func (s *Symbol) GetProbes() []*Probe {
	return s.probes
}
