package agent

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	log "github.com/sirupsen/logrus"

	lua "github.com/yuin/gopher-lua"
)

// 30 seconds
const downloadTimeout = 30

type DownloadEvent struct {
	tag      string
	callback string
	filePath string
	md5      string
	err      string
}

func (de *DownloadEvent) evtType() string {
	return "download"
}

type DownloadModule struct {
	owner *Script

	downloaderMap map[string]*Downloader
}

func newDownloaderModule(s *Script) *DownloadModule {
	dm := &DownloadModule{
		owner:         s,
		downloaderMap: make(map[string]*Downloader),
	}

	return dm
}

func (dm *DownloadModule) loader(L *lua.LState) int {
	// register functions to the table
	var exports = map[string]lua.LGFunction{
		"createDownloader": dm.createDownloadStub,
		"deleteDownloader": dm.deleteDownloadStub,
	}

	mod := L.SetFuncs(L.NewTable(), exports)

	// returns the module
	L.Push(mod)
	return 1
}

func (dm *DownloadModule) createDownloadStub(L *lua.LState) int {
	tag := L.CheckString(1)
	filePath := L.CheckString(2)
	url := L.CheckString(3)
	callback := L.CheckString(4)
	timeout := L.CheckInt64(5)
	// fmt.Println("tag ", tag, " filePath ", filePath, " url ", url, " timeout ", timeout, " callback ", callback)
	if !dm.owner.hasLuaFunction(callback) {
		L.Push(lua.LString(fmt.Sprintf("Func %s not exist", callback)))
		return 1
	}

	if len(tag) < 1 {
		L.Push(lua.LString("Must set tag"))
		return 1
	}

	if timeout <= 0 {
		timeout = downloadTimeout
	}

	_, exist := dm.downloaderMap[tag]
	if exist {
		log.Infof("downloader %s already exit", tag)
		L.Push(lua.LString(fmt.Sprintf("Download task %s already exist", tag)))
		return 1
	}

	ctx, ctxCancelFn := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	downloader := &Downloader{
		tag:         tag,
		callback:    callback,
		ctx:         ctx,
		ctxCancelFn: ctxCancelFn,
	}

	dm.downloaderMap[tag] = downloader

	go func() {
		err := downloader.donwloadFile(filePath, url)
		dv := &DownloadEvent{
			tag:      downloader.tag,
			callback: downloader.callback,
			filePath: filePath,
		}

		if err != nil {
			dv.err = fmt.Sprintf("Download failed:%s, url:%s", err.Error(), url)
		} else {
			md5, err := fileMD5(filePath)
			if err == nil {
				dv.md5 = md5
			}
		}

		dm.owner.pushEvt(dv)
	}()

	return 0
}

func (dm *DownloadModule) deleteDownloadStub(L *lua.LState) int {
	// extract tag
	tag := L.ToString(1)
	downloader, exist := dm.downloaderMap[tag]
	if !exist {
		return 0
	}

	downloader.ctxCancelFn()

	delete(dm.downloaderMap, tag)

	return 0
}

func (dm *DownloadModule) clear() {
	for _, v := range dm.downloaderMap {
		v.ctxCancelFn()
	}

	dm.downloaderMap = make(map[string]*Downloader)
}

func (dm *DownloadModule) delete(tag string) {
	delete(dm.downloaderMap, tag)
}

type Downloader struct {
	tag         string
	callback    string
	ctx         context.Context
	ctxCancelFn context.CancelFunc
}

func (downloader *Downloader) donwloadFile(filePath, url string) error {
	req, err := http.NewRequestWithContext(downloader.ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("Downloader.downloadFile status code: %d, msg: %s, url: %s", resp.StatusCode, string(body), url)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = io.Copy(file, resp.Body)
	if err != nil {
		return err
	}

	return nil
}
