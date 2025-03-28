package main

import (
	"agent/redis"
	"agent/server"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"regexp"
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
		// &cli.StringFlag{
		// 	Name:  "listen",
		// 	Usage: "--listen=0.0.0.0:8080",
		// 	Value: "0.0.0.0:8080",
		// },
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
		// listenAddress := cctx.String("listen")
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
		fmt.Println("Starting server on ", config.ListenOn)
		go func() {
			err := http.ListenAndServe(config.ListenOn, s)
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

var genSnCmd = &cli.Command{
	Name:  "gensn",
	Usage: "gen box sn with params",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:  "yymm",
			Usage: "--yymm=202502",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "batch",
			Usage: "--batch=01",
			Value: "",
		},
		&cli.StringFlag{
			Name:  "cfg",
			Usage: "--cfg=./config.yaml",
			Value: "",
		},
		&cli.IntFlag{
			Name:  "count",
			Usage: "--count=10",
			Value: 0,
		},
		&cli.BoolFlag{
			Name:  "store",
			Usage: "--store=true",
			Value: false,
		},
	},
	Action: func(cctx *cli.Context) error {
		yymm := cctx.String("yymm")
		batch := cctx.String("batch")
		count := cctx.Int("count")

		if yymm == "" || batch == "" {
			return errors.New("yymm or batch is empty")
		}

		// 判断 yymm 和 batch 格式是否正确
		yymmRegex := regexp.MustCompile(`^20\d{2}(0[1-9]|1[012])`)
		batchRegex := regexp.MustCompile(`^[1-9]$|^(0[1-9]|1[0-9]|2[0-4])$`)
		if !yymmRegex.MatchString(yymm) {
			return errors.New("yymm format error")
		}

		if !batchRegex.MatchString(batch) {
			return errors.New("batch format error")
		}

		if count <= 0 {
			return errors.New("count must greater than 0")
		}

		codes, err := generateUniqueCodes(count, 10)
		if err != nil {
			return err
		}

		var sns []string
		for _, code := range codes {
			key := fmt.Sprintf("TT%s%s%s", yymm, batch, code)
			sns = append(sns, key)
		}

		store := cctx.Bool("store")
		configFilePath := cctx.String("cfg")
		if store {
			config, err := server.ParseConfig(configFilePath)
			if err != nil {
				return err
			}

			rds := redis.NewRedis(config.RedisAddr, config.RedisPass)
			ok, err := rds.CheckExist(cctx.Context, sns)
			if err != nil {
				return err
			}
			if ok {
				return errors.New("sn repeated, please try again")
			}

			if err := rds.AddBoxSNs(cctx.Context, sns); err != nil {
				return err
			}
		}

		for _, sn := range sns {
			fmt.Println(sn)
		}

		return nil
	},
}

func generateRandomCode(length int) (string, error) {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	result := make([]byte, length)

	// 逐字符生成
	for i := 0; i < length; i++ {
		// 从 charset 中随机取一个下标
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		// 取对应字符填入 result
		result[i] = charset[idx.Int64()]
	}

	return string(result), nil
}

func generateUniqueCodes(n int, length int) ([]string, error) {
	if n <= 0 {
		return nil, fmt.Errorf("n must be > 0")
	}

	used := make(map[string]struct{}, n)
	codes := make([]string, 0, n)

	for len(codes) < n {
		code, err := generateRandomCode(length)
		if err != nil {
			return nil, err
		}

		if _, exists := used[code]; !exists {
			used[code] = struct{}{}
			codes = append(codes, code)
		}
	}

	return codes, nil
}

func main() {
	commands := []*cli.Command{
		runCmd,
		versionCmd,
		genSnCmd,
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
