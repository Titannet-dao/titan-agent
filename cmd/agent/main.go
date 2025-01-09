package main

import (
	"agent/agent"
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v2"
)

func main() {
	app := &cli.App{
		Name:  "agent",
		Usage: "Manager and update business process",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "working-dir",
				Usage:    "--working-dir=/path/to/working/dir",
				EnvVars:  []string{"WORKING_DIR"},
				Required: true,
				Value:    "",
			},
			&cli.StringFlag{
				Name:    "script-file-name",
				Usage:   "--script-file-name script.lua",
				EnvVars: []string{"SCRIPT_FILE_NAME"},
				Value:   "script.lua",
			},

			&cli.IntFlag{
				Name:    "script-interval",
				Usage:   "--script-interval 60",
				EnvVars: []string{"SCRIPT_INTERVAL"},
				Value:   60,
			},
			&cli.StringFlag{
				Name:     "server-url",
				Usage:    "--server-url http://localhost:8080/update/lua",
				EnvVars:  []string{"SERVER_URL"},
				Required: true,
				Value:    "http://localhost:8080/update/lua",
			},
			&cli.StringFlag{
				Name:  "channel",
				Usage: "--channel titan-l1, channel: titan-l1,painet,emc-titan-l2",
				Value: "",
			},
			&cli.StringFlag{
				Name:  "key",
				Usage: "--key YOUR_WEB_KEY",
				Value: "",
			},
		},
		Before: func(cctx *cli.Context) error {
			return nil
		},
		Action: func(cctx *cli.Context) error {
			agrs := &agent.AgentArguments{
				WorkingDir:     cctx.String("working-dir"),
				ScriptFileName: cctx.String("script-file-name"),

				ScriptInvterval: cctx.Int("script-interval"),
				ServerURL:       cctx.String("server-url"),
				Channel:         cctx.String("channel"),
				Key:             cctx.String("key"),
			}

			agent, err := agent.New(agrs)
			if err != nil {
				log.Fatal(err)
			}

			ctx, done := context.WithCancel(cctx.Context)
			sigChan := make(chan os.Signal, 2)
			go func() {
				<-sigChan
				done()
			}()

			signal.Notify(sigChan, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
			return agent.Run(ctx)
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
