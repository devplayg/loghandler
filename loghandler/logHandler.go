package loghandler

import (
	"github.com/astaxie/beego/orm"
	"github.com/devplayg/mserver"
	"github.com/devplayg/mserver/stats"
	"github.com/gorilla/mux"
	"sync"
)

//type LogHandler interface {
//	Start() error
//	GetName() string
//	GetLogs() []stats.ItemList
//}

type StatsDate struct {
	From string
	To   string
	Mark string
}

type EventLogHandler struct {
	name         string
	rows         interface{}
	rank         stats.DataRank
	dataMap      stats.DataMap
	_rank        stats.DataRank
	memberAssets map[int][]int
	mutex        *sync.RWMutex
	engine       *mserver.Engine
	r            *mux.Router
	o            orm.Ormer
	date         *StatsDate
}

//import (
//	"github.com/gorilla/mux"
//	"sync"
//	"time"
//"github.com/astaxie/beego/orm"
//	"github.com/devplayg/loghandler/statistics"
//)
//
//type LogHandler struct {
//	o            orm.Ormer
//	t            time.Time
//	name   string
//	Engine *Engine
//	dataMap      statistics.DataMap
//	_rank        statistics.DataRank
//	rank         statistics.DataRank
//	memberAssets map[int][]int
//	mutex        *sync.RWMutex
//	Router *mux.Router
//}
//
