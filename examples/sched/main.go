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

package main

import (
	"flag"
	"io/fs"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	tkbtf "github.com/elastic/tk-btf"
)

func loadWakeUpNewTaskSymbol(symbolMap map[string]*tkbtf.Symbol) {
	wakeUpNewTaskSymbol := tkbtf.NewSymbol("wake_up_new_task").AddProbes(
		tkbtf.NewKProbe().SetRef("wake_up_new_task").AddFetchArgs(
			tkbtf.NewFetchArg("tid", "s32").FuncParamWithName("p", "pid").FuncParamWithName("p", "", "pid"),
			tkbtf.NewFetchArg("tgid", "s32").FuncParamWithName("p", "tgid").FuncParamWithName("p", "", "tgid"),
			tkbtf.NewFetchArg("ppid", "s32").FuncParamWithName("p", "group_leader", "real_parent", "tgid").FuncParamWithName("p", "", "group_leader", "", "real_parent", "", "tgid"),
			tkbtf.NewFetchArg("stime", "u64").
				FuncParamWithName("p", "group_leader", "start_time").
				FuncParamWithName("p", "", "group_leader", "", "start_time"),
			tkbtf.NewFetchArg("pgid", "s32").
				FuncParamWithName("p", "group_leader", "pids", "enum:pid_type:PIDTYPE_PGID", "pid", "numbers", "index:0", "nr").
				FuncParamWithName("p", "", "group_leader", "", "pids", "enum:pid_type:PIDTYPE_PGID", "pid", "numbers", "index:0", "nr").
				FuncParamWithName("p", "group_leader", "signal", "pids", "enum:pid_type:PIDTYPE_PGID", "numbers", "index:0", "nr").
				FuncParamWithName("p", "", "group_leader", "", "signal", "pids", "enum:pid_type:PIDTYPE_PGID", "numbers", "index:0", "nr"),
			tkbtf.NewFetchArg("sid", "s32").
				FuncParamWithName("p", "group_leader", "pids", "enum:pid_type:PIDTYPE_SID", "pid", "numbers", "index:0", "nr").
				FuncParamWithName("p", "", "group_leader", "", "pids", "enum:pid_type:PIDTYPE_SID", "pid", "numbers", "index:0", "nr").
				FuncParamWithName("p", "group_leader", "signal", "pids", "enum:pid_type:PIDTYPE_SID", "numbers", "index:0", "nr").
				FuncParamWithName("p", "", "group_leader", "", "signal", "pids", "enum:pid_type:PIDTYPE_SID", "numbers", "index:0", "nr"),
			tkbtf.NewFetchArg("cuid", "u32").
				FuncParamWithName("p", "cred", "uid", "val").
				FuncParamWithName("p", "", "cred", "uid", "val").
				FuncParamWithName("p", "cred", "uid").
				FuncParamWithName("p", "", "cred", "uid"),
			tkbtf.NewFetchArg("cgid", "u32").
				FuncParamWithName("p", "cred", "gid", "val").
				FuncParamWithName("p", "", "cred", "gid", "val").
				FuncParamWithName("p", "cred", "gid").
				FuncParamWithName("p", "", "cred", "gid"),
			tkbtf.NewFetchArg("ceuid", "u32").
				FuncParamWithName("p", "cred", "euid", "val").
				FuncParamWithName("p", "", "cred", "euid", "val").
				FuncParamWithName("p", "cred", "euid").
				FuncParamWithName("p", "", "cred", "euid"),
			tkbtf.NewFetchArg("cegid", "u32").
				FuncParamWithName("p", "cred", "egid", "val").
				FuncParamWithName("p", "", "cred", "egid", "val").
				FuncParamWithName("p", "cred", "egid").
				FuncParamWithName("p", "", "cred", "egid"),
			tkbtf.NewFetchArg("csuid", "u32").
				FuncParamWithName("p", "cred", "suid", "val").
				FuncParamWithName("p", "", "cred", "suid", "val").
				FuncParamWithName("p", "cred", "suid").
				FuncParamWithName("p", "", "cred", "suid"),
			tkbtf.NewFetchArg("csgid", "u32").
				FuncParamWithName("p", "cred", "sgid", "val").
				FuncParamWithName("p", "", "cred", "sgid", "val").
				FuncParamWithName("p", "cred", "sgid").
				FuncParamWithName("p", "", "cred", "sgid"),
		),
	)

	symbolMap["wake_up_new_task"] = wakeUpNewTaskSymbol
}

func loadTaskStatsExitSymbol(symbolMap map[string]*tkbtf.Symbol) {
	taskStatsExitSymbol := tkbtf.NewSymbol("taskstats_exit").AddProbes(
		tkbtf.NewKProbe().SetRef("taskstats_exit").AddFetchArgs(
			tkbtf.NewFetchArg("tid", "s32").FuncParamWithName("tsk", "pid").FuncParamWithName("tsk", "", "pid"),
			tkbtf.NewFetchArg("tgid", "s32").FuncParamWithName("tsk", "tgid").FuncParamWithName("tsk", "", "tgid"),
			tkbtf.NewFetchArg("ppid", "s32").FuncParamWithName("tsk", "group_leader", "real_parent", "tgid").FuncParamWithName("tsk", "", "group_leader", "", "real_parent", "", "tgid"),
			tkbtf.NewFetchArg("stime", "u64").
				FuncParamWithName("tsk", "group_leader", "start_time").
				FuncParamWithName("tsk", "", "group_leader", "", "start_time"),
			tkbtf.NewFetchArg("pgid", "s32").
				FuncParamWithName("tsk", "group_leader", "pids", "enum:pid_type:PIDTYPE_PGID", "pid", "numbers", "index:0", "nr").
				FuncParamWithName("tsk", "", "group_leader", "", "pids", "enum:pid_type:PIDTYPE_PGID", "pid", "numbers", "index:0", "nr").
				FuncParamWithName("tsk", "group_leader", "signal", "pids", "enum:pid_type:PIDTYPE_PGID", "numbers", "index:0", "nr").
				FuncParamWithName("tsk", "", "group_leader", "", "signal", "pids", "enum:pid_type:PIDTYPE_PGID", "numbers", "index:0", "nr"),
			tkbtf.NewFetchArg("sid", "s32").
				FuncParamWithName("tsk", "group_leader", "pids", "enum:pid_type:PIDTYPE_SID", "pid", "numbers", "index:0", "nr").
				FuncParamWithName("tsk", "", "group_leader", "", "pids", "enum:pid_type:PIDTYPE_SID", "pid", "numbers", "index:0", "nr").
				FuncParamWithName("tsk", "group_leader", "signal", "pids", "enum:pid_type:PIDTYPE_SID", "numbers", "index:0", "nr").
				FuncParamWithName("tsk", "", "group_leader", "", "signal", "pids", "enum:pid_type:PIDTYPE_SID", "numbers", "index:0", "nr"),
			tkbtf.NewFetchArg("gd", "s32").FuncParamWithName("group_dead"),
			tkbtf.NewFetchArg("cuid", "u32").
				FuncParamWithName("tsk", "cred", "uid", "val").
				FuncParamWithName("tsk", "", "cred", "uid", "val").
				FuncParamWithName("tsk", "cred", "uid").
				FuncParamWithName("tsk", "", "cred", "uid"),
			tkbtf.NewFetchArg("cgid", "u32").
				FuncParamWithName("tsk", "cred", "gid", "val").
				FuncParamWithName("tsk", "", "cred", "gid", "val").
				FuncParamWithName("tsk", "cred", "gid").
				FuncParamWithName("tsk", "", "cred", "gid"),
			tkbtf.NewFetchArg("ceuid", "u32").
				FuncParamWithName("tsk", "cred", "euid", "val").
				FuncParamWithName("tsk", "", "cred", "euid", "val").
				FuncParamWithName("tsk", "cred", "euid").
				FuncParamWithName("tsk", "", "cred", "euid"),
			tkbtf.NewFetchArg("cegid", "u32").
				FuncParamWithName("tsk", "cred", "egid", "val").
				FuncParamWithName("tsk", "", "cred", "egid", "val").
				FuncParamWithName("tsk", "cred", "egid").
				FuncParamWithName("tsk", "", "cred", "egid"),
			tkbtf.NewFetchArg("csuid", "u32").
				FuncParamWithName("tsk", "cred", "suid", "val").
				FuncParamWithName("tsk", "", "cred", "suid", "val").
				FuncParamWithName("tsk", "cred", "suid").
				FuncParamWithName("tsk", "", "cred", "suid"),
			tkbtf.NewFetchArg("csgid", "u32").
				FuncParamWithName("tsk", "cred", "sgid", "val").
				FuncParamWithName("tsk", "", "cred", "sgid", "val").
				FuncParamWithName("tsk", "cred", "sgid").
				FuncParamWithName("tsk", "", "cred", "sgid"),
		),
	)

	symbolMap["taskstats_exit"] = taskStatsExitSymbol
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	symbolMap := make(map[string]*tkbtf.Symbol)

	var btfHubArchiveRepoPath string
	var validate bool
	flag.StringVar(&btfHubArchiveRepoPath, "repo", "", "path to the root folder of the btfhub-archive repository")
	flag.BoolVar(&validate, "validate", false, "if set, the tkbtf definitions are gonna be rebuilt against each generated stripped btf file")

	flag.Parse()

	if btfHubArchiveRepoPath == "" {
		flag.Usage()
		os.Exit(1)
	}

	loadWakeUpNewTaskSymbol(symbolMap)
	loadTaskStatsExitSymbol(symbolMap)

	probesTracingMap := make(map[string]struct{})

	seenBTFnames := make(map[string]interface{})
	strippedBTFsCount := 0
	err := filepath.Walk(btfHubArchiveRepoPath, func(path string, info fs.FileInfo, err error) error {
		if !strings.HasSuffix(path, ".btf") {
			return nil
		}

		if err != nil {
			logger.Warn("error walking path", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		spec, err := tkbtf.NewSpecFromPath(path, nil)
		if err != nil {
			logger.Warn("error loading spec", slog.String("path", path), slog.Any("err", err))
			return nil
		}

		var symbolsToKeep []*tkbtf.Symbol
		var newTracingProbe bool
		for symbolName, symbol := range symbolMap {
			err = spec.BuildSymbol(symbol)
			if err != nil {
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

		strippedSpecPath := path + ".sched.stripped"
		if err := spec.StripAndSave(strippedSpecPath, symbolsToKeep...); err != nil {
			logger.Warn("error stripping spec", slog.String("path", strippedSpecPath), slog.Any("err", err))
			return nil
		}
		logger.Info("produced stripped spec", slog.String("path", strippedSpecPath), slog.Int("count", strippedBTFsCount))
		strippedBTFsCount++

		strippedSpecBase := filepath.Base(strippedSpecPath)
		if _, exists := seenBTFnames[strippedSpecBase]; exists {
			logger.Warn("name collision", slog.String("name", strippedSpecBase))
		}
		seenBTFnames[strippedSpecBase] = struct{}{}

		if !validate {
			return nil
		}

		strippedSpec, err := tkbtf.NewSpecFromPath(strippedSpecPath, nil)
		if err != nil {
			logger.Warn("error loading spec from stripped btf", slog.String("path", strippedSpecPath), slog.Any("err", err))
			return nil
		}

		for symbolName, symbol := range symbolMap {
			if err := strippedSpec.BuildSymbol(symbol); err != nil {
				logger.Warn("error building symbol", slog.String("path", strippedSpecPath), slog.String("symbol", symbolName), slog.Any("err", err))
				continue
			}
		}

		return nil
	})

	if err != nil {
		log.Fatal(err)
	}
}
