package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"

	"github.com/2005Andy/claude-ip-control/internal/firewall"
	"github.com/2005Andy/claude-ip-control/internal/guard"
)

const (
	defaultGuardConfig = "/etc/claude-ip-control/guard.json"
	defaultStatusFile  = "/run/claude-ip-control/status.json"
)

func runGuard(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: claude-ip-control guard <run|once|status|clear|render-verge-script> [--config path]")
	}
	fs := flag.NewFlagSet("guard "+args[0], flag.ContinueOnError)
	path := fs.String("config", defaultGuardConfig, "path to guard JSON configuration")
	statusFile := fs.String("status-file", defaultStatusFile, "where the daemon writes its current status")
	noKernel := fs.Bool("no-kernel", false, "once: skip the nftables layer (for testing without root)")
	output := fs.String("o", "", "render-verge-script: write to this file instead of stdout")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	switch args[0] {
	case "run":
		return guardRun(ctx, *path, *statusFile)
	case "once":
		return guardOnce(ctx, *path, *noKernel)
	case "status":
		return guardStatus(ctx, *statusFile)
	case "render-verge-script":
		cfg, err := guard.LoadConfig(*path)
		if err != nil {
			return err
		}
		script, err := guard.RenderVergeScript(cfg)
		if err != nil {
			return err
		}
		if *output == "" {
			fmt.Print(script)
			return nil
		}
		return os.WriteFile(*output, []byte(script), 0o644)
	case "clear":
		if err := firewall.NewGuardKernel().Clear(ctx); err != nil {
			return err
		}
		fmt.Println("guard nftables table removed; the mihomo guard group is left as is")
		return nil
	default:
		return fmt.Errorf("unknown guard action %q", args[0])
	}
}

func guardLogger(cfg *guard.Config) (*slog.Logger, func(), error) {
	var w io.Writer = os.Stdout
	closer := func() {}
	if cfg.LogFile != "" {
		if err := os.MkdirAll(filepath.Dir(cfg.LogFile), 0o755); err != nil {
			return nil, nil, fmt.Errorf("create log directory: %w", err)
		}
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return nil, nil, fmt.Errorf("open log file: %w", err)
		}
		w, closer = io.MultiWriter(os.Stdout, f), func() { f.Close() }
	}
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})), closer, nil
}

func guardRun(ctx context.Context, path, statusFile string) error {
	cfg, err := guard.LoadConfig(path)
	if err != nil {
		return err
	}
	log, closeLog, err := guardLogger(cfg)
	if err != nil {
		return err
	}
	defer closeLog()
	g, err := guard.New(cfg, guard.NewMihomoClient(cfg.Mihomo), firewall.NewGuardKernel(), log)
	if err != nil {
		return err
	}
	g.StatusFile = statusFile
	log.Info("guard starting", "config", path, "expected_egress_ip", cfg.ExpectedEgressIP, "group", cfg.Mihomo.GuardGroup, "pinned", cfg.Mihomo.PinnedProxy)
	err = g.Run(ctx)
	log.Info("guard stopped; nftables guard table and current group selection are left in place")
	return err
}

func guardOnce(ctx context.Context, path string, noKernel bool) error {
	cfg, err := guard.LoadConfig(path)
	if err != nil {
		return err
	}
	var kernel firewall.GuardKernel = firewall.NewGuardKernel()
	if noKernel {
		kernel = skipKernel{}
	}
	g, err := guard.New(cfg, guard.NewMihomoClient(cfg.Mihomo), kernel, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err != nil {
		return err
	}
	st := g.Once(ctx)
	out, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(out))
	return nil
}

func guardStatus(ctx context.Context, statusFile string) error {
	data, err := os.ReadFile(statusFile)
	if err != nil {
		fmt.Printf("no daemon status at %s: %v\n", statusFile, err)
	} else {
		fmt.Printf("daemon status (%s):\n%s", statusFile, data)
	}
	kernel, err := firewall.NewGuardKernel().Status(ctx)
	if err != nil {
		fmt.Println("nftables:", err, "(run with sudo to read the table)")
		return nil
	}
	fmt.Print("nftables:\n", kernel)
	return nil
}

type skipKernel struct{}

func (skipKernel) Install(context.Context, []*net.IPNet, []string) error { return nil }
func (skipKernel) Clear(context.Context) error                           { return nil }
func (skipKernel) Status(context.Context) (string, error)                { return "skipped", nil }
