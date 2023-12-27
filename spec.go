package tkbtf

import (
	"errors"
	"io"
	"os"
	"runtime"

	"github.com/cilium/ebpf/btf"
)

// btf spec Interface to abstract actual specs and mock
type btfSpec interface {
	TypeByName(name string, typ interface{}) error
	AnyTypesByName(name string) ([]btf.Type, error)

	copy() btfSpec
	typeID(t btf.Type) (btf.TypeID, error)
}

type SpecOptions struct {
	arch string
}

// Spec holds the btfSpec and the registersResolver.
type Spec struct {
	spec btfSpec
	regs registersResolver
}

// btfSpecWrapper is a thin wrapper around btf.Spec to implement the btfSpec interface.
type btfSpecWrapper struct {
	spec *btf.Spec
}

// NewSpecFromKernel generates a new Spec from the kernel.
func NewSpecFromKernel() (*Spec, error) {
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		if errors.Is(err, btf.ErrNotSupported) {
			return nil, ErrSpecKernelNotSupported
		}
		return nil, err
	}

	return specFromBTF(spec, runtime.GOARCH)
}

// NewSpecFromReader generates a new Spec from the given io.ReaderAt.
func NewSpecFromReader(rd io.ReaderAt, opts *SpecOptions) (*Spec, error) {
	spec, err := btf.LoadSpecFromReader(rd)
	if err != nil {
		return nil, err
	}

	var arch string
	if opts != nil {
		arch = opts.arch
	} else {
		arch = runtime.GOARCH
	}

	return specFromBTF(spec, arch)
}

// NewSpecFromPath generates a new Spec from the given file path.
func NewSpecFromPath(path string, opts *SpecOptions) (*Spec, error) {
	spec, err := btf.LoadSpec(path)
	if err != nil {
		return nil, err
	}

	var arch string
	if opts != nil {
		arch = opts.arch
	} else {
		arch = runtime.GOARCH
	}

	return specFromBTF(spec, arch)
}

func specFromBTF(spec *btf.Spec, arch string) (*Spec, error) {
	regs, err := getRegistersResolver(arch)
	if err != nil {
		return nil, err
	}

	return &Spec{
		spec: &btfSpecWrapper{spec: spec},
		regs: regs,
	}, nil
}

// StripAndSave first extracts from all Symbols the associated btf types and respective members that are used
// to successfully construct the probes. Then based on the former it clears any unused btf types and members
// from the btf spec. Finally, it saves the btf spec with wire format to the given path.
func (s *Spec) StripAndSave(pathToSave string, symbolsToInclude ...*Symbol) error {
	btfBuilder := btf.Builder{}

	typesToKeep := make(typesToStripMap)
	for _, symbol := range symbolsToInclude {
		for _, probe := range symbol.probes {
			for _, fArg := range probe.fetchArgs {
				if builtParam := fArg.successfulBuilder; builtParam != nil {
					for fieldIndex, paramField := range builtParam.getFields() {

						if builtParam.getWrap() != WrapNone && fieldIndex == 0 {
							// if we artificially constructed the struct pointer, skip it
							continue
						}

						if paramField.parentBtfType != nil {
							if err := typesToKeep.addTypeField(s.spec, paramField.parentBtfType, paramField.name); err != nil {
								return err
							}
						}

						if err := typesToKeep.addType(s.spec, paramField.btfType); err != nil {
							return err
						}
					}
				}

				if fArg.btfFunc != nil {
					if err := typesToKeep.addType(s.spec, fArg.btfFunc); err != nil {
						return err
					}

					if err := typesToKeep.addType(s.spec, fArg.btfFunc.Type); err != nil {
						return err
					}
				}
			}
		}
	}

	specToStrip := s.spec
	s.spec = s.spec.copy()

	typesToKeep.strip(specToStrip)
	for _, typ := range typesToKeep {
		if _, err := btfBuilder.Add(typ.typ); err != nil {
			return err
		}
	}

	bytesBuffer, err := btfBuilder.Marshal(nil, nil)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(pathToSave, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	_, err = file.Write(bytesBuffer)
	if err != nil {
		return err
	}

	return file.Close()
}

// BuildSymbol builds the given symbol against the btf spec.
func (s *Spec) BuildSymbol(symbol *Symbol) error {

	// Call the build function on the symbol with the first spec
	if err := symbol.build(s.spec, s.regs); err != nil {
		// If an error occurs, return the error immediately
		return err
	}

	return nil
}

// ContainsSymbol returns true if the btf spec contains the given symbol name
func (s *Spec) ContainsSymbol(symbolName string) bool {
	var funcType *btf.Func
	return s.spec.TypeByName(symbolName, &funcType) == nil
}

func (b *btfSpecWrapper) AnyTypesByName(name string) ([]btf.Type, error) {
	return b.spec.AnyTypesByName(name)
}

func (b *btfSpecWrapper) TypeByName(name string, typ interface{}) error {
	return b.spec.TypeByName(name, typ)
}

func (b *btfSpecWrapper) typeID(typ btf.Type) (btf.TypeID, error) {
	return b.spec.TypeID(typ)
}

func (b *btfSpecWrapper) copy() btfSpec {
	return &btfSpecWrapper{
		spec: b.spec.Copy(),
	}
}
