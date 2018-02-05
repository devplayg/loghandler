package loghandler

import (
	"encoding/json"
	"fmt"
	"github.com/astaxie/beego/orm"
	"github.com/devplayg/mserver"
	"github.com/devplayg/mserver/stats"
	"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const (
	RootId = -1
)

type FileLog struct {
	Rdate          time.Time
	SensorId       int
	IppoolSrcGcode int
	IppoolSrcOcode int
	TransType      int
	SrcIp          uint32
	SrcPort        int
	DstIp          uint32
	DstPort        int
	DstCountry     string
	Domain         string
	Url            string
	Md5            string
	MailSender     string
	MailRecipient  string
	FileName           string
	MalCategory    int
	FileType       int
	FileSize       int
	FileJudge      int
	Score          int
}

type FileLogHandler EventLogHandler
type NetworkLogHandler EventLogHandler
type AgentLogHandler EventLogHandler

var tables = []string{"md5", "srcip", "dstip"}

func NewFileLogHandler(engine *mserver.Engine, router *mux.Router) *FileLogHandler {
	return &FileLogHandler{
		name:   "file",
		engine: engine,
		r:      router,
		mutex:  new(sync.RWMutex),
	}
}

func (f *FileLogHandler) Start(date *StatsDate, wg *sync.WaitGroup) error {
	go func() {
		defer wg.Done()

		execTime := make(map[string]time.Time)
		execTime["start"] = time.Now()

		f.date = date

		assets, err := mserver.GetMemberAssets()
		if err != nil {
			log.Error(err)
			return
		} else {
			f.mutex.Lock()
			f.memberAssets = assets
			f.mutex.Unlock()
		}

		// Fetch logs
		rowCount, err := f.fetchLogs()
		if err != nil {
			log.Error(err)
			return
		}
		execTime["fetching"] = time.Now()

		// Produce statistics
		f.produceStats()
		if err != nil {
			log.Error(err)
			return
		}
		execTime["stats"] = time.Now()

		// Insert
		err = f.insert()
		if err != nil {
			log.Error(err)
			return
		}
		execTime["insert"] = time.Now()

		log.Debugf("[%s] rowCount=%d, totalTime=%3.1f(s), fetchingTime=%3.1f(s), statsTime=%3.1f(s), insertTime=%3.1f(s)",
			f.GetName(),
			rowCount,
			execTime["insert"].Sub(execTime["start"]).Seconds(),
			execTime["fetching"].Sub(execTime["start"]).Seconds(),
			execTime["stats"].Sub(execTime["fetching"]).Seconds(),
			execTime["insert"].Sub(execTime["stats"]).Seconds(),
		)
	}()

	f.AddRoute()
	return nil
}

func (f *FileLogHandler) GetName() string {
	return f.name
}

func (f *FileLogHandler) fetchLogs() (int, error) {
	query := `
		select 	t.rdate,
				(sensor_id + 100000) sensor_id,
				from_unixtime(unix_timestamp(t.rdate) - (unix_timestamp(t.rdate) % 600)) every10min,
				trans_type,
				ippool_src_gcode,
				ippool_src_ocode,
				session_id,
				src_ip,
				src_port,
				src_country,
				dst_ip,
				dst_port,
				dst_country,
				domain,
				concat(domain, url) url,
				ifnull(t1.filesize, 0) file_size,
				ifnull(t1.filetype, 0) file_type,
				ifnull(t.trans_type, 0) trans_type,
				ifnull(t1.category, 0) mal_category,
				filename,				
				t.md5,
				mail_sender,
				mail_recipient,
				score,
				case
					when t1.score = 100 then 1
					when t1.score < 100 and t1.score >= 40 then 2
					else 2
				end file_judge
		from log_event_filetrans t left outer join pol_file_md5 t1 on t1.md5 = t.md5
		where t.rdate >= ? and t.rdate <= ?
	`
	var rows []FileLog
	o := orm.NewOrm()
	_, err := o.Raw(query, f.date.From, f.date.To).QueryRows(&rows)
	if err != nil {
		return 0, err
	}

	f.mutex.Lock()
	f.rows = rows
	f.mutex.Unlock()

	return len(rows), nil
}

func (f *FileLogHandler) produceStats() error {

	// Initialize
	f.dataMap = make(stats.DataMap)
	f._rank = make(stats.DataRank)
	f.dataMap[RootId] = make(map[string]map[interface{}]int64)
	f._rank[RootId] = make(map[string]stats.ItemList)

	// Count
	for _, r := range f.rows.([]FileLog) {
		f.addToStats(&r, "srcip", r.SrcIp, false)
		f.addToStats(&r, "dstip", r.DstIp, false)
		f.addToStats(&r, "md5", r.Md5, false)
		f.addToStats(&r, "dstcountry", r.DstCountry, false)
		f.addToStats(&r, "dstdomain", r.Domain, false)
		f.addToStats(&r, "dsturi", r.Url, false)
		f.addToStats(&r, "transtype", r.TransType, false)
		f.addToStats(&r, "filetype", r.FileType, false)
		f.addToStats(&r, "malcategory", r.MalCategory, false)
		f.addToStats(&r, "filejudge", r.FileJudge, false)
	}

	// Determine rankings
	for id, m := range f.dataMap {
		for category, data := range m {
			f._rank[id][category] = stats.DetermineRankings(data, 300)
		}
	}

	f.mutex.Lock()
	f.rank = f._rank
	f.mutex.Unlock()

	return nil
}

func (f *FileLogHandler) addToStats(r *FileLog, category string, val interface{}, isMalicious bool) error {

	// By sensor
	if r.SensorId > 0 {
		if _, ok := f.dataMap[r.SensorId]; !ok {
			f.dataMap[r.SensorId] = make(map[string]map[interface{}]int64)
			f._rank[r.SensorId] = make(map[string]stats.ItemList)
		}
		if _, ok := f.dataMap[r.SensorId][category]; !ok {
			f.dataMap[r.SensorId][category] = make(map[interface{}]int64)
			f._rank[r.SensorId][category] = nil
		}
		f.dataMap[r.SensorId][category][val] += 1
	}

	// By group
	if r.IppoolSrcGcode > 0 {
		if _, ok := f.dataMap[r.IppoolSrcGcode]; !ok {
			f.dataMap[r.IppoolSrcGcode] = make(map[string]map[interface{}]int64)
			f._rank[r.IppoolSrcGcode] = make(map[string]stats.ItemList)
		}
		if _, ok := f.dataMap[r.IppoolSrcGcode][category]; !ok {
			f.dataMap[r.IppoolSrcGcode][category] = make(map[interface{}]int64)
			f._rank[r.IppoolSrcGcode][category] = nil
		}
		f.dataMap[r.IppoolSrcGcode][category][val] += 1
	}

	// To all
	if _, ok := f.dataMap[RootId][category]; !ok {
		f.dataMap[RootId][category] = make(map[interface{}]int64)
		f._rank[RootId][category] = nil
	}
	f.dataMap[RootId][category][val] += 1

	// By member
	if arr, ok := f.memberAssets[r.IppoolSrcGcode]; ok {
		for _, memberId := range arr {
			id := memberId * -1

			if _, ok := f.dataMap[id]; !ok {
				f.dataMap[id] = make(map[string]map[interface{}]int64)
				f._rank[id] = make(map[string]stats.ItemList)
			}
			if _, ok := f.dataMap[id][category]; !ok {
				f.dataMap[id][category] = make(map[interface{}]int64)
				f._rank[id][category] = nil
			}
			f.dataMap[id][category][val] += 1
		}
	}

	// Malicious file
	if r.Score == 100 && !isMalicious {
		f.addToStats(r, category+"_mal", val, true)
	}
	return nil
}

func (f *FileLogHandler) insert() error {
	fm := make(map[string]*os.File)
	defer func() {
		for _, file := range fm {
			file.Close()
			os.Remove(file.Name())
		}
	}()
	for id, m := range f._rank {
		for category, list := range m {
			if _, ok := fm[category]; !ok {
				tempFile, err := ioutil.TempFile("", category+"_")
				if err != nil {
					return err
				}
				fm[category] = tempFile
			}

			for i, item := range list {
				str := fmt.Sprintf("%s\t%d\t%v\t%d\t%d\n", f.date.Mark, id, item.Key, item.Count, i+1)
				fm[category].WriteString(str)
			}
		}
	}

	o := orm.NewOrm()
	for category, file := range fm {
		file.Close()
		query := fmt.Sprintf("LOAD DATA LOCAL INFILE %q INTO TABLE stat_%s", file.Name(), category)
		_, err := o.Raw(query).Exec()
		if err == nil {
			//num, _ := res.RowsAffected()
			//log.Debugf("affectedRows=%d, category=%s", num, category)
		} else {
			return err
		}
	}

	return nil
}

func (f *FileLogHandler) RemoveJustBeforeStats() error {
	o := orm.NewOrm()
	query1 := "delete from stat_%s where (rdate >= ? and rdate <= ?) and rdate <> ?"
	query2 := "delete from stat_%s_mal where (rdate >= ? and rdate <= ?) and rdate <> ?"
	for _, tb := range tables {
		q1 := fmt.Sprintf(query1, tb)
		_, err := o.Raw(q1, f.date.From, f.date.To, f.date.Mark).Exec()
		if err != nil {
			return err
		}

		q2 := fmt.Sprintf(query2, tb)
		_, err = o.Raw(q2, f.date.From, f.date.To, f.date.Mark).Exec()
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *FileLogHandler) RemoveOldStats(date *StatsDate) error {
	log.Debugf("Remove old stats.: %s ~ %s", date.From, date.To)

	o := orm.NewOrm()
	query1 := "delete from stat_%s where rdate >= ? and rdate <= ?"
	query2 := "delete from stat_%s_mal where rdate >= ? and rdate <= ?"
	for _, tb := range tables {
		q1 := fmt.Sprintf(query1, tb)
		_, err := o.Raw(q1, date.From, date.To).Exec()
		if err != nil {
			return err
		}

		q2 := fmt.Sprintf(query2, tb)
		_, err = o.Raw(q2, date.From, date.To).Exec()
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *FileLogHandler) RemoveSpecificStats(date string) error {
	log.Debugf("Remove stats. of specific time: %s", date)

	o := orm.NewOrm()
	query1 := "delete from stat_%s where rdate = ?"
	query2 := "delete from stat_%s_mal where rdate = ?"
	for _, tb := range tables {
		q1 := fmt.Sprintf(query1, tb)
		_, err := o.Raw(q1, date).Exec()
		if err != nil {
			return err
		}

		q2 := fmt.Sprintf(query2, tb)
		_, err = o.Raw(q2, date).Exec()
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *FileLogHandler) rankAll(w http.ResponseWriter, r *http.Request) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	buf, _ := json.Marshal(f.rank)
	w.Write(buf)
}

func (f *FileLogHandler) rankHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)

	groupId, _ := strconv.Atoi(vars["groupId"])
	top, _ := strconv.Atoi(vars["top"])

	list := f.getRank(groupId, vars["category"], top)
	buf, _ := json.Marshal(list)
	w.Write(buf)
}

func (f *FileLogHandler) getRank(groupId int, category string, top int) stats.ItemList {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	if _, ok := f.rank[groupId]; ok {
		if list, ok2 := f.rank[groupId][category]; ok2 {
			if top > 0 && len(list) > top {
				return list[:top]
			} else {
				return list
			}
		}
	}
	return nil
}

func (f *FileLogHandler) AddRoute() {
	f.r.HandleFunc("/rank/{groupId:-?[0-9]+}/{category}/{top:[0-9]+}", f.rankHandler)
	f.r.HandleFunc("/rank", f.rankAll)
}

func NewNetworkLogHandler(engine *mserver.Engine, router *mux.Router) *NetworkLogHandler {
	return &NetworkLogHandler{
		name:   "network",
		engine: engine,
		r:      router,
	}
}

func (h *NetworkLogHandler) Start() error {
	return nil
}

func (h *NetworkLogHandler) GetName() string {
	return h.name
}

func (h *NetworkLogHandler) GetLogs() {
}

func NewAgentLogHandler(engine *mserver.Engine, router *mux.Router) *AgentLogHandler {
	return &AgentLogHandler{
		name:   "agent",
		engine: engine,
		r:      router,
	}
}

func (h *AgentLogHandler) Start() error {
	return nil
}

func (h *AgentLogHandler) GetName() string {
	return h.name
}

func (h *AgentLogHandler) GetLogs() {
}
