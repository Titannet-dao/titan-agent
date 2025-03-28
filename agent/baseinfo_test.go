package agent

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func TestGetBaseInfo(t *testing.T) {
	// memory, err := ghw.Memory()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// fmt.Println(memory.JSONString(true))

	// blk, err := ghw.Block()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// // blk.Disks[0].Model = "test"
	// fmt.Println(blk.JSONString(true))

	// gpu, err := ghw.GPU()
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// fmt.Println(gpu.JSONString(true))

	baseinfo := NewBaseInfo(&AgentInfo{}, &AppInfo{})
	fmt.Println(baseinfo)
	// blk.Disks

	// storage.
	// 	fmt.Println(memory.JSONString(true))
}

func TestScriptPrint(t *testing.T) {

	needPrint := true
	var cmd = exec.Command("/Users/zt/Desktop/agent/ctr/apps/airship-darwin/install-airship.sh", "install")
	parentEnv := os.Environ()
	cmd.Env = append(cmd.Env, parentEnv...)

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()

	stdoutBuffer := bytes.Buffer{}
	stderrBuffer := bytes.Buffer{}

	go func() {
		reader := bufio.NewReader(stdoutPipe)
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				stdoutBuffer.WriteString(line)
				if needPrint {
					fmt.Print(line) // Print to console or log
				}
			}
			if err != nil {
				break
			}
		}
	}()

	go func() {
		reader := bufio.NewReader(stderrPipe)
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 {
				stderrBuffer.WriteString(line)
				if needPrint {
					fmt.Print(line) // Print to console or log
				}
			}
			if err != nil {
				break
			}
		}
	}()

	if err := cmd.Start(); err != nil {
		log.Printf("Error starting command: %v", err)
		return
	}

	done := make(chan error)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case <-time.After(30 * time.Second):
		_ = cmd.Process.Kill()
		log.Println("command timed out")
	case err := <-done:

		if err != nil {
			if exiterr, ok := err.(*exec.ExitError); ok {
				if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
					log.Println("Exit Status:", status.ExitStatus())
				}
			}
		} else {
			log.Println("Exit Status:", 0)
		}
		log.Println("stdout:", stdoutBuffer.String())
		log.Println("stderr:", stderrBuffer.String())
	}

}
