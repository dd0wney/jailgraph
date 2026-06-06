// Command jailgraph learns a Linux program's sandbox behavior (syscalls, file
// opens, exec, process tree) and stores it as a graph in graphdb.
//
// Usage:
//
//	jailgraph learn [flags] -- <target> [args...]
//	jailgraph learn --replay events.json [flags]   # cross-platform, no tracing
//
// The capture path (seccomp user-notify) is Linux-only; --replay feeds recorded
// events through the same ingest pipeline on any platform.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/dd0wney/jailgraph/internal/aggregate"
	"github.com/dd0wney/jailgraph/internal/audit"
	"github.com/dd0wney/jailgraph/internal/buffer"
	"github.com/dd0wney/jailgraph/internal/collector"
	"github.com/dd0wney/jailgraph/internal/detect"
	"github.com/dd0wney/jailgraph/internal/ebpf"
	"github.com/dd0wney/jailgraph/internal/esf"
	"github.com/dd0wney/jailgraph/internal/graphdb"
	"github.com/dd0wney/jailgraph/internal/harden"
	"github.com/dd0wney/jailgraph/internal/ingest"
	"github.com/dd0wney/jailgraph/internal/profile"
	"github.com/dd0wney/jailgraph/internal/run"
	"github.com/dd0wney/jailgraph/internal/seccomp"
)

func main() {
	// If this process is the stage-2 traced child, install the filter and exec
	// the target — this must run before any other startup logic.
	if handled, err := seccomp.MaybeRunChild(); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, "jailgraph (traced child):", err)
			os.Exit(1)
		}
		return
	}

	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "learn":
		err = runLearn(os.Args[2:])
	case "profile":
		err = runProfile(os.Args[2:])
	case "audit":
		err = runAudit(os.Args[2:])
	case "detect":
		err = runDetect(os.Args[2:])
	case "report":
		err = runReport(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		code, msg := resolveExit(err)
		if msg != "" {
			fmt.Fprintln(os.Stderr, "jailgraph:", msg)
		}
		os.Exit(code)
	}
}

// exitErr lets a subcommand request a specific process exit code.
type exitErr struct {
	code int
	msg  string
}

func (e *exitErr) Error() string { return e.msg }

// resolveExit maps an error to a process exit code and an optional stderr
// message. An exitErr carries an explicit code (audit distinguishes drift-found
// from couldn't-audit, and uses an empty message when the report was already
// printed); everything else is a generic failure (code 1).
func resolveExit(err error) (code int, msg string) {
	var ee *exitErr
	if errors.As(err, &ee) {
		return ee.code, ee.msg
	}
	return 1, err.Error()
}

// splitCSV splits a comma-separated flag value into trimmed, non-empty parts.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// graphClient is the graphdb surface the subcommands need (satisfied by
// *graphdb.Client). It is built via newGraphClient, a seam tests override with a
// fake so the subcommand logic is unit-testable without a real server.
type graphClient interface {
	ingest.GraphClient
	profile.GraphClient
}

var newGraphClient = func(baseURL, apiKey string) graphClient {
	return graphdb.New(graphdb.Config{BaseURL: baseURL, APIKey: apiKey})
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage:")
	fmt.Fprintln(os.Stderr, "  jailgraph learn [flags] -- <target> [args...]")
	fmt.Fprintln(os.Stderr, "  jailgraph profile --run <id> [--format firejail|seccomp|both] [--out <path>] [--force]")
	fmt.Fprintln(os.Stderr, "  jailgraph audit --baseline <id[,id...]> --against <id> [--mode security|reproducibility] [--json] [--force]")
	fmt.Fprintln(os.Stderr, "  jailgraph detect --run <id> [--json] [--force]")
	fmt.Fprintln(os.Stderr, "  jailgraph report --run <id[,id...]> [--json] [--force]")
	os.Exit(2)
}

// runAudit compares a candidate run against a trusted (unioned) baseline and
// reports drift. Exit codes: 0 = no drift, 1 = drift detected, 2 = could not
// audit (missing run, lossy without --force, or setup error).
func runAudit(argv []string) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	var (
		graphURL = fs.String("graphdb-url", envOr("JAILGRAPH_GRAPHDB_URL", "http://localhost:8080"), "graphdb base URL")
		apiKey   = fs.String("api-key", os.Getenv("JAILGRAPH_API_KEY"), "graphdb API key (X-API-Key)")
		baseCSV  = fs.String("baseline", "", "comma-separated trusted baseline run id(s); unioned (required)")
		against  = fs.String("against", "", "candidate run id to audit (required)")
		modeStr  = fs.String("mode", "security", "security | reproducibility")
		jsonOut  = fs.Bool("json", false, "emit the report as JSON")
		force    = fs.Bool("force", false, "audit even if a run was lossy")
	)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *baseCSV == "" || *against == "" {
		return &exitErr{2, "--baseline and --against are required"}
	}
	mode := audit.Mode(*modeStr)
	if mode != audit.ModeSecurity && mode != audit.ModeReproducibility {
		return &exitErr{2, fmt.Sprintf("unknown --mode %q (want security|reproducibility)", *modeStr)}
	}

	client := newGraphClient(*graphURL, *apiKey)
	ctx := context.Background()

	collect := func(id string) (profile.Behavior, error) {
		b, err := profile.Collect(ctx, client, id, 500)
		if err != nil {
			return b, &exitErr{2, err.Error()}
		}
		if b.Lossy && !*force {
			return b, &exitErr{2, fmt.Sprintf("run %s was lossy; audit is unreliable. Re-run with --force to override", id)}
		}
		return b, nil
	}

	var bases []profile.Behavior
	baseIDs := splitCSV(*baseCSV)
	for _, id := range baseIDs {
		b, err := collect(id)
		if err != nil {
			return err
		}
		bases = append(bases, b)
	}
	cand, err := collect(*against)
	if err != nil {
		return err
	}

	report := audit.Diff(audit.Union(bases...), cand)
	report.BaselineRuns = baseIDs
	report.CandidateRun = *against

	if *jsonOut {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(report.RenderText(mode))
	}

	if report.DriftDetected(mode) {
		return &exitErr{1, ""} // report already printed
	}
	return nil
}

// runDetect runs the offline structural ransomware analyzer over one run's
// file-activity. Exit codes mirror audit: 0 = no High/Critical detection, 1 =
// ransomware signature found (report already printed), 2 = could not run (missing
// run, lossy without --force, bad flags). Detection needs a write-capturing
// backend (eBPF on Linux, esf on macOS); otherwise the report says so.
func runDetect(argv []string) error {
	fs := flag.NewFlagSet("detect", flag.ContinueOnError)
	var (
		graphURL = fs.String("graphdb-url", envOr("JAILGRAPH_GRAPHDB_URL", "http://localhost:8080"), "graphdb base URL")
		apiKey   = fs.String("api-key", os.Getenv("JAILGRAPH_API_KEY"), "graphdb API key (X-API-Key)")
		runID    = fs.String("run", "", "run id to analyze for ransomware signals (required)")
		jsonOut  = fs.Bool("json", false, "emit the report as JSON")
		force    = fs.Bool("force", false, "analyze even if the run was lossy")
	)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if *runID == "" {
		return &exitErr{2, "--run is required"}
	}

	client := newGraphClient(*graphURL, *apiKey)
	summary, err := detect.Collect(context.Background(), client, *runID, 500)
	if err != nil {
		return &exitErr{2, err.Error()}
	}
	if summary.Lossy && !*force {
		return &exitErr{2, fmt.Sprintf("run %s was lossy; detection is degraded. Re-run with --force to override", *runID)}
	}

	report := detect.Analyze(summary)
	if *jsonOut {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(report.RenderText())
	}
	if report.HasHighOrAbove() {
		return &exitErr{1, ""} // report already printed
	}
	return nil
}

// runReport generates an evidence-based hardening report for one program from
// one or more (unioned) runs. A hardening report describes a single program, so
// there is nothing to diff against — runs are unioned to widen the evidence
// (FullCoverage is AND-ed, so eBPF∪seccomp is honestly partial). Exit codes
// mirror audit: 0 = no finding at/above High, 1 = High/Critical present (report
// already printed), 2 = could not run (missing run, lossy without --force, or
// bad flags).
func runReport(argv []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	var (
		graphURL = fs.String("graphdb-url", envOr("JAILGRAPH_GRAPHDB_URL", "http://localhost:8080"), "graphdb base URL")
		apiKey   = fs.String("api-key", os.Getenv("JAILGRAPH_API_KEY"), "graphdb API key (X-API-Key)")
		runCSV   = fs.String("run", "", "run id(s) to report on; comma-separated runs are unioned (required)")
		jsonOut  = fs.Bool("json", false, "emit the report as JSON")
		force    = fs.Bool("force", false, "report even from a lossy (incomplete) trace")
	)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ids := splitCSV(*runCSV)
	if len(ids) == 0 {
		return &exitErr{2, "--run is required"}
	}

	client := newGraphClient(*graphURL, *apiKey)
	ctx := context.Background()

	collect := func(id string) (profile.Behavior, error) {
		b, err := profile.Collect(ctx, client, id, 500)
		if err != nil {
			return b, &exitErr{2, err.Error()}
		}
		if b.Lossy && !*force {
			return b, &exitErr{2, fmt.Sprintf("run %s was lossy; report is degraded. Re-run with --force to override", id)}
		}
		return b, nil
	}

	var behaviors []profile.Behavior
	for _, id := range ids {
		b, err := collect(id)
		if err != nil {
			return err
		}
		behaviors = append(behaviors, b)
	}

	report := harden.Analyze(profile.Union(strings.Join(ids, ","), behaviors...))
	if *jsonOut {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(report.RenderText())
	}
	if report.HasHighOrAbove() {
		return &exitErr{1, ""} // report already printed
	}
	return nil
}

func runLearn(argv []string) error {
	fs := flag.NewFlagSet("learn", flag.ContinueOnError)
	var (
		graphURL   = fs.String("graphdb-url", envOr("JAILGRAPH_GRAPHDB_URL", "http://localhost:8080"), "graphdb base URL")
		apiKey     = fs.String("api-key", os.Getenv("JAILGRAPH_API_KEY"), "graphdb API key (X-API-Key)")
		bufSize    = fs.Int("buffer", 8192, "capture ring-buffer capacity")
		batchSize  = fs.Int("batch", ingest.DefaultBatchSize, "graphdb batch size (max 1000)")
		replay     = fs.String("replay", "", "replay recorded BehaviorEvents from a JSON file instead of tracing")
		collectorK = fs.String("collector", defaultCollector(), "capture backend: seccomp | ebpf (Linux) | esf (macOS)")
	)
	// Split flags from the target command at "--".
	flagArgs, target, targetArgs := splitArgs(argv)
	if err := fs.Parse(flagArgs); err != nil {
		return err
	}
	if *replay == "" && target == "" {
		return fmt.Errorf("no target command given (expected: ... -- <target> [args...])")
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	coll, label, err := buildCollector(*replay, *collectorK, target, targetArgs)
	if err != nil {
		return err
	}

	sess := run.New(label, time.Now())
	// Only the eBPF backend observes the full syscall set; seccomp and replay
	// are partial (a tight default-deny profile needs full coverage).
	if *replay == "" && *collectorK == "ebpf" {
		sess.Coverage = run.CoverageFull
	} else {
		sess.Coverage = run.CoveragePartial
	}
	// The eBPF and macOS (eslogger) backends capture file writes/renames/unlinks
	// — the signal the ransomware detector needs. seccomp and replay do not.
	if *replay == "" && (*collectorK == "ebpf" || *collectorK == "esf") {
		sess.WriteCapture = true
	}
	builder := aggregate.New(sess.ID)
	ring := buffer.New(*bufSize)

	events, err := coll.Start(ctx)
	if err != nil {
		return fmt.Errorf("start collector: %w", err)
	}
	defer func() { _ = coll.Close() }()

	// Pump collector → ring (non-blocking; the ring accounts for any drops).
	pumpDone := make(chan struct{})
	go func() {
		defer close(pumpDone)
		for e := range events {
			ring.Push(e)
		}
	}()
	// Surface non-fatal collector errors; never swallow them.
	go func() {
		for e := range coll.Errors() {
			logger.Warn("collector error", "err", e)
		}
	}()

	// Consume ring → builder until capture ends and the ring is drained.
	// sawLossy captures upstream (collector-side) drops propagated via the event.
	var sawLossy bool
	drain := func() int {
		batch := ring.Drain(*batchSize)
		for _, e := range batch {
			if e.Lossy {
				sawLossy = true
			}
			builder.Add(e)
		}
		return len(batch)
	}
consume:
	for {
		n := drain()
		select {
		case <-pumpDone:
			for drain() > 0 {
			}
			break consume
		default:
			if n == 0 {
				time.Sleep(time.Millisecond)
			}
		}
	}
	_ = coll.Wait()

	// Finalize the session with lossiness derived from ring drops.
	sess.EndedAt = time.Now()
	if ring.TotalDropped() > 0 || sawLossy {
		sess.Lossy = true
		for kind, count := range ring.Drops() {
			sess.Dropped[kind.String()] = count
		}
		logger.Warn("trace was lossy; profile derived from it will be incomplete",
			"ring_dropped", ring.TotalDropped(), "collector_dropped", sawLossy)
	}

	// Flush to graphdb.
	client := newGraphClient(*graphURL, *apiKey)
	worker := ingest.NewWorker(client, logger, ingest.WithCacheRebuild(true), ingest.WithBatchSize(*batchSize))
	stats, err := worker.Flush(ctx, sess, builder)
	if err != nil {
		return fmt.Errorf("flush to graphdb: %w", err)
	}
	logger.Info("learn complete", "run", sess.ID, "lossy", sess.Lossy,
		"nodes_created", stats.NodesCreated, "edges_created", stats.EdgesCreated)
	return nil
}

// runProfile generates sandbox profiles from a previously-learned run.
func runProfile(argv []string) error {
	fs := flag.NewFlagSet("profile", flag.ContinueOnError)
	var (
		graphURL = fs.String("graphdb-url", envOr("JAILGRAPH_GRAPHDB_URL", "http://localhost:8080"), "graphdb base URL")
		apiKey   = fs.String("api-key", os.Getenv("JAILGRAPH_API_KEY"), "graphdb API key (X-API-Key)")
		runID    = fs.String("run", "", "Run id(s) to profile; comma-separated runs are unioned (recommended before --enforce) (required)")
		format   = fs.String("format", "firejail", "output format: firejail | seccomp | both")
		out      = fs.String("out", "", "write to this file/prefix instead of stdout")
		force    = fs.Bool("force", false, "generate even from a lossy (incomplete) trace")
		enforce  = fs.Bool("enforce", false, "emit an ENFORCING least-privilege seccomp profile (full-coverage runs only; default is safe complain/LOG mode)")
	)
	if err := fs.Parse(argv); err != nil {
		return err
	}
	ids := splitCSV(*runID)
	if len(ids) == 0 {
		return fmt.Errorf("--run is required")
	}

	client := newGraphClient(*graphURL, *apiKey)
	ctx := context.Background()
	var behaviors []profile.Behavior
	for _, id := range ids {
		bi, err := profile.Collect(ctx, client, id, 500)
		if err != nil {
			return err
		}
		behaviors = append(behaviors, bi)
	}
	// Union the runs: a single run misses error/signal/rare-branch paths, so an
	// enforce-safe baseline should span representative runs. Coverage is AND.
	b := profile.Union(strings.Join(ids, ","), behaviors...)
	// Lossy guard: an incomplete trace yields an over-restrictive profile that
	// can break the program. Refuse unless explicitly forced.
	if b.Lossy && !*force {
		return fmt.Errorf("run %s was lossy (incomplete trace); profile would be over-restrictive. Re-run with --force to override", *runID)
	}

	if *enforce && !b.FullCoverage {
		return fmt.Errorf("--enforce needs a full-coverage run (trace with --collector ebpf); run %s has partial coverage", *runID)
	}
	seccompOpts := profile.SeccompOptions{Enforce: *enforce}

	switch *format {
	case "firejail":
		return emit(*out, ".profile", []byte(profile.RenderFirejail(b)))
	case "seccomp":
		data, err := profile.RenderSeccompOCI(b, seccompOpts)
		if err != nil {
			return err
		}
		return emit(*out, ".seccomp.json", data)
	case "both":
		if err := emit(*out, ".profile", []byte(profile.RenderFirejail(b))); err != nil {
			return err
		}
		data, err := profile.RenderSeccompOCI(b, seccompOpts)
		if err != nil {
			return err
		}
		return emit(*out, ".seccomp.json", data)
	default:
		return fmt.Errorf("unknown --format %q (want firejail|seccomp|both)", *format)
	}
}

// emit writes data to stdout (when out is empty) or to out+suffix.
func emit(out, suffix string, data []byte) error {
	if out == "" {
		_, err := os.Stdout.Write(append(data, '\n'))
		return err
	}
	path := out + suffix
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "wrote", path)
	return nil
}

// buildCollector returns the chosen live-trace backend, or a FakeCollector
// replaying a fixture. The label names the run's target.
func buildCollector(replay, kind, target string, targetArgs []string) (collector.Collector, string, error) {
	if replay != "" {
		events, err := loadFixture(replay)
		if err != nil {
			return nil, "", fmt.Errorf("load replay fixture: %w", err)
		}
		return collector.NewFake(events), "replay:" + replay, nil
	}
	switch kind {
	case "seccomp":
		coll, err := seccomp.NewSupervisor(target, targetArgs, seccomp.Config{})
		return coll, target, err
	case "ebpf":
		coll, err := ebpf.NewCollector(target, targetArgs, ebpf.Config{})
		return coll, target, err
	case "esf":
		coll, err := esf.NewCollector(target, targetArgs, esf.Config{})
		return coll, target, err
	default:
		return nil, "", fmt.Errorf("unknown --collector %q (want seccomp|ebpf|esf)", kind)
	}
}

// defaultCollector picks the OS-native capture backend: eslogger on macOS,
// seccomp on Linux. (Both eBPF and seccomp are Linux-only; esf is macOS-only.)
func defaultCollector() string {
	if runtime.GOOS == "darwin" {
		return "esf"
	}
	return "seccomp"
}

func loadFixture(path string) ([]collector.BehaviorEvent, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var events []collector.BehaviorEvent
	if err := json.Unmarshal(data, &events); err != nil {
		return nil, err
	}
	return events, nil
}

// splitArgs separates flags (before "--") from the target command (after).
func splitArgs(argv []string) (flags []string, target string, targetArgs []string) {
	for i, a := range argv {
		if a == "--" {
			flags = argv[:i]
			rest := argv[i+1:]
			if len(rest) > 0 {
				target = rest[0]
				targetArgs = rest[1:]
			}
			return flags, target, targetArgs
		}
	}
	return argv, "", nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
