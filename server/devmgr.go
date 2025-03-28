package server

import (
	"agent/redis"
	"context"
	"encoding/json"
	"reflect"
	"sync"
	"time"

	goredis "github.com/redis/go-redis/v9"
	log "github.com/sirupsen/logrus"
)

const (
	keepaliveInterval = 30 * time.Second
	offlineTime       = 300 * time.Second
)

type Controller struct {
	NodeID string
	Device
}

type Agent struct {
	Device
}

type DevMgr struct {
	agents      sync.Map
	controllers sync.Map
	redis       *redis.Redis
}

func NodeOfflineTime() time.Duration {
	return offlineTime
}

func newDevMgr(ctx context.Context, redis *redis.Redis) *DevMgr {
	dm := &DevMgr{redis: redis}
	go dm.startTicker(ctx)

	return dm
}

func (dm *DevMgr) startTicker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			dm.keepalive()
		case <-ctx.Done():
			return
		}
	}
}

func (dm *DevMgr) keepalive() {
	offlineAgents := make([]*Agent, 0)
	dm.agents.Range(func(key, value any) bool {
		d := value.(*Agent)
		if d != nil && time.Since(d.LastActivityTime) > offlineTime {
			offlineAgents = append(offlineAgents, d)
		}
		return true
	})

	for _, d := range offlineAgents {
		dm.removeAgent(d)
	}

	offlineControllers := make([]*Controller, 0)
	dm.controllers.Range(func(key, value any) bool {
		d := value.(*Controller)
		if d != nil && time.Since(d.LastActivityTime) > offlineTime {
			offlineControllers = append(offlineControllers, d)
		}
		return true
	})

	for _, controller := range offlineControllers {
		dm.removeController(controller)
	}
}

func (dm *DevMgr) addAgent(agent *Agent) {
	dm.agents.Store(agent.UUID, agent)
}

func (dm *DevMgr) removeAgent(agent *Agent) {
	dm.agents.Delete(agent.UUID)
}

func (dm *DevMgr) getAgent(uuid string) *Agent {
	v, ok := dm.agents.Load(uuid)
	if !ok {
		return nil
	}
	return v.(*Agent)
}

func (dm *DevMgr) getAgents() []*Agent {
	agents := make([]*Agent, 0)
	dm.agents.Range(func(key, value any) bool {
		d := value.(*Agent)
		if d != nil {
			agents = append(agents, d)
		}
		return true
	})

	return agents
}

func (dm *DevMgr) updateAgent(ag *Agent) {
	if len(ag.UUID) == 0 {
		return
	}

	agent := dm.getAgent(ag.UUID)
	if agent == nil {
		dm.addAgent(ag)
		return
	}

	agent.LastActivityTime = ag.LastActivityTime
}

func (dm *DevMgr) addController(controller *Controller) {
	dm.controllers.Store(controller.NodeID, controller)
}

func (dm *DevMgr) removeController(controller *Controller) {
	dm.controllers.Delete(controller.NodeID)
}

func (dm *DevMgr) getController(nodeID string) *Controller {
	v, ok := dm.controllers.Load(nodeID)
	if !ok {
		return nil
	}
	return v.(*Controller)
}

func (dm *DevMgr) getControllers() []*Controller {
	controllers := make([]*Controller, 0)
	dm.controllers.Range(func(key, value any) bool {
		d := value.(*Controller)
		if d != nil {
			controllers = append(controllers, d)
		}
		return true
	})

	return controllers
}

// func (dm *DevMgr) updateController(c *Controller, serviceState int) {
// 	if len(c.NodeID) == 0 {
// 		log.Errorf("updateController empty nodeID")
// 		return
// 	}

// 	if c.AndroidSerialNumber != "" && redis.BoxSNPattern.MatchString(c.AndroidSerialNumber) {
// 		ok, err := dm.redis.CheckExist(context.Background(), []string{c.AndroidSerialNumber})
// 		if err != nil {
// 			log.Errorf("updateController redis.CheckExist error: %v", err)
// 			return
// 		}
// 		if !ok {
// 			log.Errorf("updateController serialNumber not in whitelist: %s", c.AndroidSerialNumber)
// 			return
// 		}
// 	}

// 	// log.Info("set controller ", c.NodeID)
// 	controller := dm.getController(c.NodeID)
// 	if controller == nil {
// 		dm.addController(c)
// 		return
// 	}

// 	cNode := controllerToNode(c)
// 	cNode.ServiceState = serviceState
// 	cNode.LastActivityTime = time.Now()
// 	// cNode.AndroidSerialNumber = controller.AndroidSerialNumber
// 	if err := dm.redis.SetNode(context.Background(), cNode); err != nil {
// 		log.Errorf("updateController redis.SetNode error: %v", err)
// 	}

// 	if err := dm.redis.IncrNodeOnlineDuration(context.Background(), controller.NodeID, int(cNode.LastActivityTime.Sub(controller.LastActivityTime).Seconds())); err != nil {
// 		log.Errorf("updateController redis.IncrNodeOnlineDuration error: %v", err)
// 	}

// 	controller.LastActivityTime = cNode.LastActivityTime
// }

func controllerToNode(c *Controller) *redis.Node {
	buf, err := json.Marshal(c)
	if err != nil {
		log.Error("controllerToNode ", err.Error())
		return nil
	}

	node := &redis.Node{}
	err = json.Unmarshal(buf, node)
	if err != nil {
		log.Error("controllerToNode ", err.Error())
		return nil
	}

	node.ID = c.NodeID
	node.UUID = c.Device.UUID
	// node.LastActivityTime = time.Now()
	return node
}

func (dm *DevMgr) updateNodeFromDevice(ctx context.Context, nodeid string, d *Device, svcst int) {
	if len(nodeid) == 0 {
		log.Errorf("updateNodeFromDevice empty nodeID")
		return
	}

	if d.AndroidSerialNumber != "" && redis.BoxSNPattern.MatchString(d.AndroidSerialNumber) {
		ok, err := dm.redis.CheckExist(context.Background(), []string{d.AndroidSerialNumber})
		if err != nil {
			log.Errorf("updateNodeFromDevice redis.CheckExist error: %v", err)
			return
		}
		if !ok {
			log.Errorf("updateNodeFromDevice serialNumber not in whitelist: %s", d.AndroidSerialNumber)
			return
		}
	}

	rNode, err := dm.redis.GetNode(ctx, nodeid)
	if err != nil && err != goredis.Nil {
		log.Errorf("updateNodeFromDevice redis.GetNode error: %v", err)
		return
	}

	if rNode == nil {
		rNode = &redis.Node{}
	}

	var lstAt = rNode.LastActivityTime

	copyNoEmptyFields(rNode, d)

	rNode.ServiceState = svcst
	rNode.LastActivityTime = time.Now()
	rNode.ID = nodeid

	if err := dm.redis.SetNode(context.Background(), rNode); err != nil {
		log.Errorf("updateNodeFromDevice redis.SetNode error: %v", err)
	}

	duration := int(time.Since(lstAt).Seconds())
	if duration > 0 && !lstAt.IsZero() {
		if err := dm.redis.IncrNodeOnlineDuration(context.Background(), nodeid, duration); err != nil {
			log.Errorf("updateNode redis.IncrNodeOnlineDuration error: %v", err)
		}
	}
	// if err := dm.redis.IncrNodeOnlineDuration(context.Background(), nodeid, int(time.Since(lstAt).Seconds())); err != nil {
	// 	log.Errorf("updateNodeFromDevice redis.IncrNodeOnlineDuration error: %v", err)
	// }
}

func (dm *DevMgr) updateNode(ctx context.Context, nodeid string, rNode *redis.Node, svcst int) {
	if len(nodeid) == 0 {
		log.Errorf("updateNode empty nodeID")
		return
	}

	if rNode.AndroidSerialNumber != "" && redis.BoxSNPattern.MatchString(rNode.AndroidSerialNumber) {
		ok, err := dm.redis.CheckExist(context.Background(), []string{rNode.AndroidSerialNumber})
		if err != nil {
			log.Errorf("updateNode redis.CheckExist error: %v", err)
			return
		}
		if !ok {
			log.Errorf("updateNode serialNumber not in whitelist: %s", rNode.AndroidSerialNumber)
			return
		}
	}

	// lstAt := rNode.LastActivityTime
	rNode.ServiceState = svcst
	rNode.LastActivityTime = time.Now()

	if err := dm.redis.SetNode(context.Background(), rNode); err != nil {
		log.Errorf("updateNode redis.SetNode error: %v", err)
	}

}

func copyNoEmptyFields(dest, src interface{}) {
	destVal := reflect.ValueOf(dest).Elem()
	srcVal := reflect.ValueOf(src).Elem()
	destType := destVal.Type()

	for i := 0; i < destVal.NumField(); i++ {
		fieldName := destType.Field(i).Name
		destField := destVal.Field(i)
		srcField := srcVal.FieldByName(fieldName)

		if !srcField.IsValid() {
			// empty fileds will be ignored
			continue
		}

		// only copy in non-zero value
		switch srcField.Kind() {
		case reflect.String:
			if srcField.String() != "" {
				destField.SetString(srcField.String())
			}
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if srcField.Int() != 0 {
				destField.SetInt(srcField.Int())
			}
		case reflect.Float32, reflect.Float64:
			if srcField.Float() != 0.0 {
				destField.SetFloat(srcField.Float())
			}
		case reflect.Bool:
			if srcField.Bool() {
				destField.SetBool(srcField.Bool())
			}
		case reflect.Struct:
			// especially for time.Time
			if srcField.Type() == reflect.TypeOf(time.Time{}) {
				if !srcField.Interface().(time.Time).IsZero() {
					destField.Set(srcField)
				}
			}
		}
	}
}
