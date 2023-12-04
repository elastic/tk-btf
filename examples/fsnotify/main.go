package main

import (
	"errors"
	"flag"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	tkbtf "github.com/elastic/tk-btf"
)

const (
	fsEventModify    = uint32(0x00000002)
	fsEventAttrib    = uint32(0x00000004)
	fsEventMovedFrom = uint32(0x00000040)
	fsEventMovedTo   = uint32(0x00000080)
	fsEventCreate    = uint32(0x00000100)
	fsEventDelete    = uint32(0x00000200)
	fsEventIsDir     = uint32(0x40000000)
)

const (
	devMajor = uint32(0xFFF00000)
	devMinor = uint32(0x3FF)
)

func loadFSNotifySymbol(symbolMap map[string]*tkbtf.Symbol) {
	fsNotifySymbol := tkbtf.NewSymbol("fsnotify").AddProbes(
		// Kprobe for fsnotify with FSNOTIFY_EVENT_PATH (data_type==1)
		tkbtf.NewKProbe().SetID("fsnotify_path").AddFetchArgs(
			tkbtf.NewFetchArg("pi", "u64").FuncParamWithCustomType("data", tkbtf.WrapPointer, "path", "dentry", "d_parent", "d_inode", "i_ino"),
			tkbtf.NewFetchArg("mc", tkbtf.BitFieldTypeMask(fsEventCreate)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("md", tkbtf.BitFieldTypeMask(fsEventDelete)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("ma", tkbtf.BitFieldTypeMask(fsEventAttrib)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mm", tkbtf.BitFieldTypeMask(fsEventModify)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mid", tkbtf.BitFieldTypeMask(fsEventIsDir)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mmt", tkbtf.BitFieldTypeMask(fsEventMovedTo)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mmf", tkbtf.BitFieldTypeMask(fsEventMovedFrom)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("fi", "u64").FuncParamWithCustomType("data", tkbtf.WrapPointer, "path", "dentry", "d_inode", "i_ino"),
			tkbtf.NewFetchArg("dt", "s32").FuncParamWithName("data_type").FuncParamWithName("data_is"),
			tkbtf.NewFetchArg("pdmj", tkbtf.BitFieldTypeMask(devMajor)).FuncParamWithCustomType("data", tkbtf.WrapPointer, "path", "dentry", "d_inode", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("pdmn", tkbtf.BitFieldTypeMask(devMinor)).FuncParamWithCustomType("data", tkbtf.WrapPointer, "path", "dentry", "d_inode", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("fn", "string").FuncParamWithCustomType("data", tkbtf.WrapPointer, "path", "dentry", "d_name", "name"),
		),
		// Kprobe for fsnotify with FSNOTIFY_EVENT_INODE (data_type==2)
		tkbtf.NewKProbe().SetID("fsnotify_inode").AddFetchArgs(
			tkbtf.NewFetchArg("pi", "u64").FuncParamWithName("dir", "i_ino").FuncParamWithName("to_tell", "i_ino"),
			tkbtf.NewFetchArg("mc", tkbtf.BitFieldTypeMask(fsEventCreate)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("md", tkbtf.BitFieldTypeMask(fsEventDelete)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("ma", tkbtf.BitFieldTypeMask(fsEventAttrib)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mm", tkbtf.BitFieldTypeMask(fsEventModify)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mid", tkbtf.BitFieldTypeMask(fsEventIsDir)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mmt", tkbtf.BitFieldTypeMask(fsEventMovedTo)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mmf", tkbtf.BitFieldTypeMask(fsEventMovedFrom)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("nptr", "u64").FuncParamWithName("file_name"),
			tkbtf.NewFetchArg("fi", "u64").FuncParamWithCustomType("data", tkbtf.WrapPointer, "inode", "i_ino"),
			tkbtf.NewFetchArg("dt", "s32").FuncParamWithName("data_type").FuncParamWithName("data_is"),
			tkbtf.NewFetchArg("pdmj", tkbtf.BitFieldTypeMask(devMajor)).FuncParamWithName("dir", "i_sb", "s_dev").FuncParamWithName("to_tell", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("pdmn", tkbtf.BitFieldTypeMask(devMinor)).FuncParamWithName("dir", "i_sb", "s_dev").FuncParamWithName("to_tell", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("fn", "string").FuncParamWithName("file_name", "name").FuncParamWithName("file_name"),
		),
		// Kprobe for fsnotify with FSNOTIFY_EVENT_DENTRY (data_type==3)
		tkbtf.NewKProbe().SetID("fsnotify_dentry").AddFetchArgs(
			tkbtf.NewFetchArg("pi", "u64").FuncParamWithCustomType("data", tkbtf.WrapPointer, "dentry", "d_parent", "d_inode", "i_ino"),
			tkbtf.NewFetchArg("mc", tkbtf.BitFieldTypeMask(fsEventCreate)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("md", tkbtf.BitFieldTypeMask(fsEventDelete)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("ma", tkbtf.BitFieldTypeMask(fsEventAttrib)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mm", tkbtf.BitFieldTypeMask(fsEventModify)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mid", tkbtf.BitFieldTypeMask(fsEventIsDir)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mmt", tkbtf.BitFieldTypeMask(fsEventMovedTo)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mmf", tkbtf.BitFieldTypeMask(fsEventMovedFrom)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("fi", "u64").FuncParamWithCustomType("data", tkbtf.WrapPointer, "dentry", "d_inode", "i_ino"),
			tkbtf.NewFetchArg("dt", "s32").FuncParamWithName("data_type").FuncParamWithName("data_is"),
			tkbtf.NewFetchArg("pdmj", tkbtf.BitFieldTypeMask(devMajor)).FuncParamWithCustomType("data", tkbtf.WrapPointer, "dentry", "d_inode", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("pdmn", tkbtf.BitFieldTypeMask(devMinor)).FuncParamWithCustomType("data", tkbtf.WrapPointer, "dentry", "d_inode", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("fn", "string").FuncParamWithCustomType("data", tkbtf.WrapPointer, "dentry", "d_name", "name"),
		),
	)

	symbolMap["fsnotify"] = fsNotifySymbol
}

func loadFSNotifyParentSymbol(symbolMap map[string]*tkbtf.Symbol) {
	fsNotifyParentSymbol := tkbtf.NewSymbol("__fsnotify_parent", "fsnotify_parent").AddProbes(
		tkbtf.NewKProbe().AddFetchArgs(
			tkbtf.NewFetchArg("pi", "u64").FuncParamWithName("dentry", "d_parent", "d_inode", "i_ino"),
			tkbtf.NewFetchArg("mc", tkbtf.BitFieldTypeMask(fsEventCreate)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("md", tkbtf.BitFieldTypeMask(fsEventDelete)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("ma", tkbtf.BitFieldTypeMask(fsEventAttrib)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mm", tkbtf.BitFieldTypeMask(fsEventModify)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mid", tkbtf.BitFieldTypeMask(fsEventIsDir)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mmt", tkbtf.BitFieldTypeMask(fsEventMovedTo)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("mmf", tkbtf.BitFieldTypeMask(fsEventMovedFrom)).FuncParamWithName("mask"),
			tkbtf.NewFetchArg("fi", "u64").FuncParamWithName("dentry", "d_inode", "i_ino"),
			tkbtf.NewFetchArg("pdmj", tkbtf.BitFieldTypeMask(devMajor)).FuncParamWithName("dentry", "d_parent", "d_inode", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("pdmn", tkbtf.BitFieldTypeMask(devMinor)).FuncParamWithName("dentry", "d_parent", "d_inode", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("fn", "string").FuncParamWithName("dentry", "d_name", "name"),
		),
	)

	symbolMap["fsnotify_parent"] = fsNotifyParentSymbol
}

func loadFSNotifyNameRemoveSymbol(symbolMap map[string]*tkbtf.Symbol) {
	fsNotifyParentSymbol := tkbtf.NewSymbol("fsnotify_nameremove").AddProbes(
		tkbtf.NewKProbe().AddFetchArgs(
			tkbtf.NewFetchArg("pi", "u64").FuncParamWithName("dentry", "d_parent", "d_inode", "i_ino"),
			tkbtf.NewFetchArg("mid", "u32").FuncParamWithName("isdir"),
			tkbtf.NewFetchArg("fi", "u64").FuncParamWithName("dentry", "d_inode", "i_ino"),
			tkbtf.NewFetchArg("pdmj", tkbtf.BitFieldTypeMask(devMajor)).FuncParamWithName("dentry", "d_inode", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("pdmn", tkbtf.BitFieldTypeMask(devMinor)).FuncParamWithName("dentry", "d_inode", "i_sb", "s_dev"),
			tkbtf.NewFetchArg("fn", "string").FuncParamWithName("dentry", "d_name", "name"),
		),
	)

	symbolMap["fsnotify_nameremove"] = fsNotifyParentSymbol
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	symbolMap := make(map[string]*tkbtf.Symbol)

	var btfHubArchiveRepoPath string
	flag.StringVar(&btfHubArchiveRepoPath, "repo", "", "path to the root folder of the btfhub-archive repository")

	flag.Parse()

	if btfHubArchiveRepoPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	loadFSNotifySymbol(symbolMap)
	loadFSNotifyParentSymbol(symbolMap)
	loadFSNotifyNameRemoveSymbol(symbolMap)

	probesTracingMap := make(map[string]struct{})

	err := filepath.Walk(btfHubArchiveRepoPath, func(path string, info fs.FileInfo, err error) error {
		if !strings.HasSuffix(path, ".btf") {
			return nil
		}

		if err != nil {
			logger.Warn("error walking path", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		spec, err := tkbtf.NewSpecFromPath(path)
		if err != nil {
			logger.Warn("error loading spec", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		var symbolsToKeep []*tkbtf.Symbol
		var newTracingProbe bool
		for symbolName, symbol := range symbolMap {
			err = spec.BuildSymbol(symbol)
			if err != nil {
				if symbolName == "fsnotify_nameremove" && errors.Is(err, tkbtf.ErrSymbolNotFound) {
					continue
				}
				logger.Warn("error building symbol", slog.String("path", path), slog.String("symbol", symbolName), slog.Any("err", err))
				continue
			}

			symbolsToKeep = append(symbolsToKeep, symbol)

			for _, p := range symbol.GetProbes() {
				probeKey := p.GetSymbolName() + p.GetTracingEventProbe() + p.GetTracingEventFilter()
				if _, exists := probesTracingMap[probeKey]; !exists {
					probesTracingMap[probeKey] = struct{}{}
					newTracingProbe = true
				}
			}
		}

		if !newTracingProbe {
			return nil
		}

		strippedSpecPath := path + ".stripped"
		if err := spec.StripAndSave(strippedSpecPath, symbolsToKeep...); err != nil {
			logger.Warn("error stripping spec", slog.String("path", strippedSpecPath), slog.Any("err", err))
			return nil
		}
		logger.Info("produced stripped spec", slog.String("path", strippedSpecPath))

		return nil
	})

	if err != nil {
		log.Fatal(err)
	}
}
