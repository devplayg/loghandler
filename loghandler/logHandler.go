package loghandler

import (
	"github.com/astaxie/beego/orm"
	"github.com/devplayg/mserver"
	"github.com/devplayg/mserver/stats"
	"github.com/gorilla/mux"
	"sync"
)

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
	top          int
}
