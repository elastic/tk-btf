package tkbtf

import (
	"errors"
	"fmt"

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
	return &Symbol{
		names:          symbolNames,
		skipValidation: false,
	}
}

// NewSymbolWithoutValidation creates and returns a new Symbol instance
// which during build won't try to extract the function prototype from the btf spec.
// This is useful in case the function prototype is not available in the btf spec.
func NewSymbolWithoutValidation(symbolNames ...string) *Symbol {
	return &Symbol{
		names: symbolNames,
		// Set skipValidation field to true to indicate that no validation should be performed.
		skipValidation: true,
	}
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

	// If skipValidation is false, validate each symbol until the first successfully validated
	if !s.skipValidation {
		var allErr error
		for _, symbolName := range s.names {
			err := spec.TypeByName(symbolName, &funcType)
			if err != nil {
				allErr = errors.Join(allErr, fmt.Errorf("getting func of %s failed: %w", symbolName, ErrSymbolNotFound))
				continue
			}

			s.foundSymbolName = symbolName
			break
		}

		if funcType == nil {
			return allErr
		}

		if s.foundSymbolName == "" {
			allErr = errors.Join(allErr, fmt.Errorf("could not find any symbol: %w", ErrSymbolNotFound))
			return allErr
		}
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
