// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

//go:build !windows

package tests

import (
	"fmt"
	"os"
	"time"

	ec "github.com/cilium/tetragon/api/v1/tetragon/codegen/eventchecker"
	"github.com/cilium/tetragon/pkg/bpf"
	lc "github.com/cilium/tetragon/pkg/matchers/listmatcher"
	sm "github.com/cilium/tetragon/pkg/matchers/stringmatcher"
	"github.com/cilium/tetragon/pkg/testutils/policytest"
)

// This file contains one representative policytest per hook type, labeled
// "disable-process-cache". These tests intentionally avoid asserting on the
// exported process's binary name (i.e. they never call
// ec.NewProcessChecker().WithBinary(...)), since with --disable-process-cache
// the process is reconstructed from the raw execve_map and that information
// may not be available for the event. Checks on arguments decoded directly
// from the traced function/tracepoint (e.g. file paths, buffers) are still
// used, since those come from BPF-side argument parsing and are unaffected
// by the process cache being disabled.

var _ = policytest.NewBuilder("dpc-kprobe-lseek").WithLabels("disable-process-cache").
	WithSkip(func(si *policytest.SkipInfo) string {
		if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
			return "resolve requires kernel support for large programs (v5.3 or newer)"
		}
		if si.ParamValues["Hook"] == "fentries" {
			if !si.AgentInfo.Probes[bpf.Fentry] {
				return "fentry hook depends on fentry support"
			}
			return ""
		}
		return ""
	}).WithParameter(policytest.Parameter{
	Name:    "Hook",
	Default: "kprobes",
	Values:  []any{"kprobes", "fentries"},
	Help:    "type of hook to use in the policy",
}).WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "dpc-kprobe-lseek"
spec:
  {{ .Hook }}:
  - call: "sys_lseek"
    return: false
    syscall: true
    args:
    - index: 0
      type: "int"
    data:
    - index: 0
      type: "string"
      source: "current_task"
      resolve: "comm"
    selectors:
    - matchBinaries:
      - operator: In
        values:
        - {{ testBinary "lseek-pipe" }}
      matchData:
      - index: 0
        operator: "Equal"
        values:
        - "lseek-pipe"
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	lseek := c.TestBinary("lseek-pipe")
	checker := ec.NewProcessKprobeChecker("dpc-kprobe-lseek").
		WithFunctionName(sm.Suffix("sys_lseek")).
		WithData(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("lseek-pipe")),
			))
	return &policytest.Scenario{
		Name:         "execute lseek and check kprobe event",
		Trigger:      policytest.NewCmdTrigger(lseek, "-1", "0", "4444"),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("dpc-tracepoint-exec").WithLabels("disable-process-cache").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "dpc-tracepoint-exec"
spec:
  tracepoints:
  - subsystem: "syscalls"
    event: "sys_enter_execve"
    args:
    - index: 5
      type: "string"
`).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	nop := c.TestBinary("nop")
	checker := ec.NewProcessTracepointChecker("dpc-tracepoint-exec").
		WithSubsys(sm.Full("syscalls")).
		WithEvent(sm.Full("sys_enter_execve")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full(nop)),
			))

	return &policytest.Scenario{
		Name:         "execute nop and check tracepoint event",
		Trigger:      policytest.NewCmdTrigger(nop),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("dpc-rawtracepoint-exec").WithLabels("disable-process-cache").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "dpc-rawtracepoint-exec"
spec:
  tracepoints:
  - subsystem: "sched"
    event: "sched_process_exec"
    raw: true
    args:
    - index: 2
      type: "file"
      resolve: "file"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "resolve requires kernel support for large programs (v5.3 or newer)"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	nop := c.TestBinary("nop")
	checker := ec.NewProcessTracepointChecker("dpc-rawtracepoint-exec").
		WithSubsys(sm.Full("sched")).
		WithEvent(sm.Full("sched_process_exec")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(nop))),
			))
	return &policytest.Scenario{
		Name:         "execute nop and check raw tracepoint event",
		Trigger:      policytest.NewCmdTrigger(nop),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("dpc-uprobe-nop").WithLabels("disable-process-cache").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "dpc-uprobe-nop"
spec:
  uprobes:
  - path: {{ testBinary "nop" }}
    symbols:
    - "main"
    data:
    - index: 0
      type: "string"
      source: "current_task"
      resolve: "comm"
    selectors:
    - matchData:
      - index: 0
        operator: "Equal"
        values:
        - "nop"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "resolve requires kernel support for large programs (v5.3 or newer)"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	nop := c.TestBinary("nop")
	checker := ec.NewProcessUprobeChecker("dpc-uprobe-nop").
		WithSymbol(sm.Full("main")).
		WithData(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithStringArg(sm.Full("nop")),
			))
	return &policytest.Scenario{
		Name:         "execute nop and check uprobe event",
		Trigger:      policytest.NewCmdTrigger(nop),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("dpc-usdt-test4b").WithLabels("disable-process-cache").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "dpc-usdt-test4b"
spec:
  usdts:
  - path: {{ testBinary "usdt-override" }}
    provider: "tetragon"
    name: "test_4B"
    args:
    - index: 0
      type: "int32"
    - index: 1
      type: "int32"
    - index: 2
      type: "int32"
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}
	if !si.AgentInfo.Probes[bpf.UprobeRefCtrOffsetProbe] {
		return "need uprobe ref_ctr_off support"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	myBin := c.TestBinary("usdt-override")
	checker := ec.NewProcessUsdtChecker("dpc-usdt-test4b").
		WithProvider(sm.Full("tetragon")).
		WithName(sm.Full("test_4B")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithIntArg(0),
				ec.NewKprobeArgumentChecker().WithIntArg(321),
				ec.NewKprobeArgumentChecker().WithIntArg(123),
			))
	return &policytest.Scenario{
		Name:         "execute usdt-override and check usdt event",
		Trigger:      policytest.NewCmdTrigger(myBin, "321", "123").ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()

var _ = policytest.NewBuilder("dpc-lsm-file-open").WithLabels("disable-process-cache").WithPolicyTemplate(`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "dpc-lsm-file-open"
spec:
  lsmhooks:
  - hook: "file_open"
    args:
      - index: 0
        type: "file"
    selectors:
    - matchArgs:
      - args: [0]
        operator: "Postfix"
        values: ["-target"]
`).WithSkip(func(si *policytest.SkipInfo) string {
	if !si.AgentInfo.Probes[bpf.LargeProgsProbe] {
		return "need 5.3 or newer kernel"
	}
	if !si.AgentInfo.Probes[bpf.LsmProbe] {
		return "Need LSM Support"
	}
	return ""
}).AddScenario(func(c *policytest.Conf) *policytest.Scenario {
	testBin := c.TestBinary("direct-write-tester")

	// Use /var/tmp rather than the default temp dir since
	// direct-write-tester opens its target with O_DIRECT, which fails
	// with EINVAL on tmpfs (the usual backing for /tmp). Match on the
	// path by suffix in the policy above, since the full path isn't
	// known until the scenario runs.
	targetFile := fmt.Sprintf("/var/tmp/dpc-lsm-file-open-%d-%d-target", os.Getpid(), time.Now().UnixNano())

	checker := ec.NewProcessLsmChecker("dpc-lsm-file-open").
		WithFunctionName(sm.Suffix("file_open")).
		WithArgs(ec.NewKprobeArgumentListMatcher().
			WithOperator(lc.Ordered).
			WithValues(
				ec.NewKprobeArgumentChecker().WithFileArg(ec.NewKprobeFileChecker().WithPath(sm.Full(targetFile)))))

	return &policytest.Scenario{
		Name:         "open a temp file and check lsm event",
		Trigger:      policytest.NewCmdTrigger(testBin, targetFile).ExpectExitCode(0),
		EventChecker: ec.NewUnorderedEventChecker(checker),
	}
}).RegisterAtInit()
