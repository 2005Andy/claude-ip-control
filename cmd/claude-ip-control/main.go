package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/2005Andy/claude-ip-control/internal/config"
	"github.com/2005Andy/claude-ip-control/internal/controller"
	"github.com/2005Andy/claude-ip-control/internal/firewall"
)

const sampleConfig = `{
  "refresh_interval": "10m",
  "targets": [
    {
      "name": "anthropic",
      "domains": ["claude.ai", "api.anthropic.com"]
    },
    {
      "name": "openai",
      "domains": ["chatgpt.com", "api.openai.com"]
    }
  ],
  "allowlist": [
    "203.0.113.10/32"
  ]
}
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "init":
		return initConfig(args[1:])
	case "check":
		return applyOrCheck(args[1:], false)
	case "apply":
		return applyOrCheck(args[1:], true)
	case "run":
		return runDaemon(args[1:])
	case "clear":
		return clearRules(args[1:])
	case "status":
		return showStatus()
	case "guard":
		return runGuard(args[1:])
	case "version":
		fmt.Println("claude-ip-control dev")
		return nil
	default:
		return usageError()
	}
}

func usageError() error {
	return errors.New("usage: claude-ip-control <init|check|apply|run|clear|status|guard|version> [--config path]")
}

func configPath(fs *flag.FlagSet) *string {
	return fs.String("config", config.DefaultPath(), "path to JSON configuration")
}

func initConfig(args []string) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	path := configPath(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if _, err := os.Stat(*path); err == nil {
		return fmt.Errorf("config already exists: %s", *path)
	}
	if err := os.MkdirAll(filepath.Dir(*path), 0o700); err != nil {
		return fmt.Errorf("create config directory: %w", err)
	}
	if err := os.WriteFile(*path, []byte(sampleConfig), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	fmt.Printf("created %s; replace the example allowlist before applying rules\n", *path)
	return nil
}

func applyOrCheck(args []string, apply bool) error {
	fs := flag.NewFlagSet("apply", flag.ContinueOnError)
	path := configPath(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	c := controller.New(firewall.New())
	if !apply {
		plan, err := c.BuildPlan(ctx, cfg)
		if err != nil {
			return err
		}
		fmt.Println(controller.FormatPlan(plan))
		return nil
	}
	plan, err := c.Apply(ctx, cfg)
	if err != nil {
		return err
	}
	fmt.Printf("%s: %s\n", c.Firewall.Name(), controller.FormatPlan(plan))
	return nil
}

func runDaemon(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	path := configPath(fs)
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	c := controller.New(firewall.New())
	apply := func() error {
		plan, err := c.Apply(ctx, cfg)
		if err != nil {
			return err
		}
		fmt.Printf("%s: %s\n", c.Firewall.Name(), controller.FormatPlan(plan))
		return nil
	}
	if err := apply(); err != nil {
		return err
	}
	ticker := time.NewTicker(cfg.RefreshInterval)
	defer ticker.Stop()
	fmt.Printf("watching DNS every %s; rules remain installed when the process exits (use clear to remove them)\n", cfg.RefreshInterval)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := apply(); err != nil {
				fmt.Fprintln(os.Stderr, "refresh failed; keeping the previous firewall rules:", err)
			}
		}
	}
}

func clearRules(args []string) error {
	fs := flag.NewFlagSet("clear", flag.ContinueOnError)
	if err := fs.Parse(args); err != nil {
		return err
	}
	ctx, cancel := signalContext()
	defer cancel()
	if err := firewall.New().Clear(ctx); err != nil {
		return err
	}
	fmt.Println("managed firewall rules cleared")
	return nil
}

func showStatus() error {
	ctx, cancel := signalContext()
	defer cancel()
	status, err := firewall.New().Status(ctx)
	if err != nil {
		return err
	}
	if status == "" {
		return nil
	}
	fmt.Print(status)
	return nil
}

func signalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	return ctx, cancel
}
