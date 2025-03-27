package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// **嵌入前端 HTML 文件**
//
//go:embed index.html
var frontend embed.FS

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

var nodeConns = make(map[string]*websocket.Conn)
var webClients = make(map[*websocket.Conn]bool)
var requestMap = make(map[string]*websocket.Conn)
var lock = sync.Mutex{}

func nodeHandler(conn *websocket.Conn) {
	defer conn.Close()

	ip := strings.Split(conn.RemoteAddr().String(), ":")[0]
	fmt.Println("新节点连接:", ip)

	lock.Lock()
	nodeConns[ip] = conn
	lock.Unlock()

	for {
		_, result, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("节点断开:", ip)
			lock.Lock()
			delete(nodeConns, ip)
			delete(requestMap, ip)
			lock.Unlock()
			return
		}

		fmt.Println("节点返回数据:", ip, "->", string(result))

		lock.Lock()
		webConn, exists := requestMap[ip]
		delete(requestMap, ip)
		lock.Unlock()

		if exists {
			webConn.WriteMessage(websocket.TextMessage, result)
		} else {
			fmt.Println("⚠️ 找不到原始请求的 Web 连接，丢弃数据")
		}
	}
}

func webHandler(conn *websocket.Conn) {
	defer func() {
		lock.Lock()
		delete(webClients, conn)
		lock.Unlock()
		conn.Close()
	}()

	lock.Lock()
	webClients[conn] = true
	lock.Unlock()

	fmt.Println("前端连接成功")

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}

		parts := strings.SplitN(string(msg), ":", 2)
		if len(parts) < 2 {
			conn.WriteMessage(websocket.TextMessage, []byte("ERROR: Invalid format"))
			continue
		}

		ip, cmd := parts[0], parts[1]
		fmt.Println("前端请求：节点IP =", ip, "命令 =", cmd)

		lock.Lock()
		nodeConn, exists := nodeConns[ip]
		if exists {
			requestMap[ip] = conn
		}
		lock.Unlock()

		if !exists {
			conn.WriteMessage(websocket.TextMessage, []byte("ERROR: Node not found"))
			continue
		}

		nodeConn.WriteMessage(websocket.TextMessage, []byte(cmd))
	}
}

func pushNodeList() {
	for {
		time.Sleep(5 * time.Second)

		lock.Lock()
		var nodes []string
		for ip := range nodeConns {
			nodes = append(nodes, ip)
		}
		lock.Unlock()

		nodeListMsg := "NODES:" + strings.Join(nodes, ",")
		for conn := range webClients {
			conn.WriteMessage(websocket.TextMessage, []byte(nodeListMsg))
		}

		fmt.Println("推送在线节点:", nodes)
	}
}

func main() {
	// **提供前端网页**
	http.Handle("/", http.FileServer(http.FS(frontend)))

	http.HandleFunc("/ws/node", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("WebSocket 升级失败:", err)
			return
		}
		nodeHandler(conn)
	})

	http.HandleFunc("/ws/web", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Println("WebSocket 升级失败:", err)
			return
		}
		webHandler(conn)
	})

	go pushNodeList()
	fmt.Println("服务器启动，访问 http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
