package controller

import (
	"agent/agent"
	"context"
	"crypto/md5"
	"fmt"
	"os"
	"path"

	log "github.com/sirupsen/logrus"
)

type AppArguments struct {
	ControllerArgs *ConrollerArgs
	AppConfig      *AppConfig
}

type Application struct {
	baseInfo *agent.BaseInfo
	args     *AppArguments

	script *agent.Script

	scriptFileMD5     string
	scriptFileContent []byte

	ctx       context.Context
	ctxCancel context.CancelFunc
	stopCh    chan bool

	controller *Controller
}

func NewApplication(args *AppArguments, controller *Controller) (*Application, error) {
	controllerInfo := agent.ControllerInfo{
		WorkingDir:      args.ControllerArgs.WorkingDir,
		Version:         Version,
		ServerURL:       args.ControllerArgs.ServerURL,
		ScriptInvterval: args.ControllerArgs.ScriptUpdateInterval,
		Channel:         args.ControllerArgs.Channel,
	}
	appInfo := &agent.AppInfo{
		ControllerInfo: controllerInfo,
		AppRootDir:     path.Join(args.ControllerArgs.WorkingDir, args.ControllerArgs.RelAppsDir),
		AppDir:         path.Join(args.ControllerArgs.WorkingDir, args.ControllerArgs.RelAppsDir, args.AppConfig.AppDir),
	}
	info := agent.NewBaseInfo(nil, appInfo)

	ctx, cancel := context.WithCancel(context.Background())
	app := &Application{
		baseInfo:   info,
		args:       args,
		stopCh:     make(chan bool),
		ctx:        ctx,
		ctxCancel:  cancel,
		controller: controller,
	}

	if err := app.loadScript(); err != nil {
		return nil, err
	}

	app.renewScript()

	return app, nil
}

func (app *Application) Stop() {
	// app.eventsChan <- &StopEvent{}
	app.ctxCancel()
	<-app.stopCh
	log.Printf("app %s stop", app.args.AppConfig.AppName)
}

func (app *Application) Run() error {
	loop := true

	for loop {
		script := app.currentScript()
		select {
		case ev := <-script.Events():
			script.HandleEvent(ev)
		case metric := <-script.Metric():
			log.Info("metric:", metric)
			appMetric := AppMetric{
				AppConfig: AppConfig{AppName: app.args.AppConfig.AppName},
				Metric:    metric,
			}
			// for test
			if app.controller != nil {
				app.controller.pushMetric(appMetric)
			}
		case <-app.ctx.Done():
			script.Stop()
			loop = false
			log.Info("ctx done, Run() will quit")
		}
	}

	app.stopCh <- true
	return nil
}

func (app *Application) currentScript() *agent.Script {
	return app.script
}

func (app *Application) renewScript() {
	oldScript := app.script
	if oldScript != nil {
		oldScript.Stop()
	}

	// appDir := path.Join(app.args.AppsWorkingDir, app.args.AppConfig.AppDir)
	script := agent.NewScript(app.baseInfo, app.scriptFileMD5, app.scriptFileContent)
	script.Start()

	app.script = script
}

func (app *Application) loadScript() error {
	controllerArgs := app.args.ControllerArgs
	scriptPath := path.Join(controllerArgs.WorkingDir, controllerArgs.RelAppsDir, app.args.AppConfig.AppDir, app.args.AppConfig.ScriptName)
	b, err := os.ReadFile(scriptPath)
	if err != nil {
		return err
	}

	app.scriptFileContent = b
	app.scriptFileMD5 = fmt.Sprintf("%x", md5.Sum(b))

	return nil
}
