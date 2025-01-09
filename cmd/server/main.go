package main

import (
	"agent/server"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v2"
)

const version = "0.1.0"

var versionCmd = &cli.Command{
	Name: "version",
	Before: func(cctx *cli.Context) error {
		return nil
	},
	Action: func(cctx *cli.Context) error {
		fmt.Println(version)
		return nil
	},
}

var runCmd = &cli.Command{
	Name:  "run",
	Usage: "run agent server",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "listen",
			Usage: "--listen=0.0.0.0:8080",
			Value: "0.0.0.0:8080",
		},
		&cli.StringFlag{
			Name:  "file-server",
			Usage: "--file-server ./my-file-server",
			Value: "./",
		},
		&cli.StringFlag{
			Name:  "config",
			Usage: "--config ./config.json",
			Value: "./config.json",
		},
	},

	Before: func(cctx *cli.Context) error {
		return nil
	},
	Action: func(cctx *cli.Context) error {
		listenAddress := cctx.String("listen")
		configFilePath := cctx.String("config")
		fileServerDir := cctx.String("file-server")

		config, err := server.ParseConfig(configFilePath)
		if err != nil {
			return err
		}

		_ = config
		s, err := server.NewServer(config)
		if err != nil {
			return fmt.Errorf("failed to create server: %v", err)
		}

		http.Handle("/", http.FileServer(http.Dir(fileServerDir)))

		// Start the server
		fmt.Println("Starting server on ", listenAddress)
		go func() {
			err := http.ListenAndServe(listenAddress, s)
			if err != nil {
				fmt.Println("Start server failed ", err.Error())
			}
		}()

		// Create a channel to receive OS signals
		sigChannel := make(chan os.Signal, 1)

		// Notify the channel on interrupt (Ctrl+C), kill, or terminate signals
		signal.Notify(sigChannel, syscall.SIGINT, syscall.SIGTERM)

		// Block until a signal is received
		sig := <-sigChannel

		// Print the received signal and gracefully exit
		fmt.Printf("Received signal: %s\n", sig)
		fmt.Println("Exiting gracefully...")
		return nil
	},
}

func main() {
	commands := []*cli.Command{
		runCmd,
		versionCmd,
	}

	app := &cli.App{
		Name:     "server",
		Usage:    "Manager and update business process",
		Commands: commands,
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
