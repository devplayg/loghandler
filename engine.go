package mserver

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"github.com/astaxie/beego/orm"
	"github.com/devplayg/golibs/crypto"
	"github.com/devplayg/mserver/objs"
	_ "github.com/go-sql-driver/mysql"
	"github.com/oschwald/geoip2-golang"
	log "github.com/sirupsen/logrus"
	"github.com/yl2chen/cidranger"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
)

const (
	DateDefault = "2006-01-02 15:04:05"
)

var (
	CmdFlags *flag.FlagSet
	encKey   []byte
)

func init() {
	CmdFlags = flag.NewFlagSet("", flag.ExitOnError)
	key := sha256.Sum256([]byte("D?83F4 E?E"))
	encKey = key[:]
}

type Engine struct {
	ConfigPath  string
	Config      map[string]string
	Interval    int64
	appName     string
	debug       bool
	cpuCount    int
	processName string
	logOutput   int // 0: STDOUT, 1: File
	GeoIP2      *geoip2.Reader
	IpPoolMap   map[int]cidranger.Ranger
}

func NewEngine(appName string, debug bool, cpuCount int, interval int64, verbose bool) *Engine {
	e := Engine{
		appName:     appName,
		processName: strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0])),
		cpuCount:    cpuCount,
		debug:       debug,
		Interval:    interval,
	}
	e.ConfigPath = filepath.Join(filepath.Dir(os.Args[0]), e.processName+".enc")
	e.initLogger(verbose)
	return &e
}

func (e *Engine) Start() error {
	var err error

	e.Config, err = e.getConfig()
	if err != nil {
		return err
	}
	if _, ok := e.Config["db.hostname"]; !ok {
		return errors.New("invalid configurations")
	}

	err = e.initDatabase()
	if err != nil {
		return err
	}

	err = e.loadGeoIP()
	if err != nil {
		return err
	}

	err = e.loadIpPool()
	if err != nil {
		return err
	}

	log.Debug("Engine started")
	runtime.GOMAXPROCS(e.cpuCount)
	log.Debugf("GOMAXPROCS set to %d", runtime.GOMAXPROCS(0))
	return nil
}

func (e *Engine) loadIpPool() error {
	// IPPool 조회
	query := "select sensor_id, folder_id, ippool_id, name, concat(ip, '/', cidr) ip_cidr from ast_ippool"
	var ippools []objs.IpPool
	o := orm.NewOrm()
	_, err := o.Raw(query).QueryRows(&ippools)
	if err != nil {
		return err
	}

	// 센서별 IP Pool 분류
	e.IpPoolMap = make(map[int]cidranger.Ranger)
	for _, a := range ippools {
		a.UpdateIpNet()
		if _, ok := e.IpPoolMap[a.SensorId]; !ok {
			ranger := cidranger.NewPCTrieRanger()
			e.IpPoolMap[a.SensorId] = ranger
		}

		r := e.IpPoolMap[a.SensorId]
		err := r.Insert(a)
		if err != nil {
			log.Debug(err)
		}
	}

	return nil
}

func (e *Engine) loadGeoIP() error {
	geoIpPath, _ := filepath.Abs(os.Args[0])
	geoIpPath = filepath.Join(filepath.Dir(geoIpPath), "libs", "GeoLite2-Country.mmdb")
	ipDB, err := geoip2.Open(geoIpPath)
	if err != nil {
		return err
	}
	e.GeoIP2 = ipDB

	return nil
}

func (e *Engine) initLogger(verbose bool) error {
	// Set log format
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		DisableColors: true,
	})

	// Set log level
	if e.debug {
		log.SetLevel(log.DebugLevel)
		orm.Debug = false
	}

	if verbose {
		e.logOutput = 0
		log.SetOutput(os.Stdout)
		orm.DebugLog = orm.NewLog(os.Stdout)
	} else {
		var logFile string
		if e.debug {
			logFile = filepath.Join(filepath.Dir(os.Args[0]), e.processName+"-debug.log")
			os.Remove(logFile)

		} else {
			logFile = filepath.Join(filepath.Dir(os.Args[0]), e.processName+".log")
		}

		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0666)
		if err == nil {
			log.SetOutput(file)
			e.logOutput = 1
			orm.DebugLog = orm.NewLog(file)
		} else {
			e.logOutput = 0
			log.SetOutput(os.Stdout)
			orm.DebugLog = orm.NewLog(os.Stdout)
		}
	}

	if log.GetLevel() != log.InfoLevel {
		log.Infof("LoggingLevel=%s", log.GetLevel())
	}

	return nil
}

func (e *Engine) initDatabase() error {
	connStr := fmt.Sprintf(
		"%s:%s@tcp(%s:%s)/%s?allowAllFiles=true&charset=utf8&parseTime=true&loc=%s",
		e.Config["db.username"],
		e.Config["db.password"],
		e.Config["db.hostname"],
		e.Config["db.port"],
		e.Config["db.database"],
		"Asia%2FSeoul")
	log.Debugf("[db] hostname=%s, username=%s, port=%s, database=%s", e.Config["db.hostname"], e.Config["db.username"], e.Config["db.port"], e.Config["db.database"])
	err := orm.RegisterDataBase("default", "mysql", connStr, 3, 3)
	return err
}

func WaitForSignals() {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	select {
	case <-signalCh:
		log.Println("Signal received, shutting down...")
	}
}

func (e *Engine) getConfig() (map[string]string, error) {
	if _, err := os.Stat(e.ConfigPath); os.IsNotExist(err) {
		return nil, errors.New("configuration file not found (use '-config' option)")
	} else {
		config := make(map[string]string)
		err := crypto.LoadEncryptedObjectFile(e.ConfigPath, encKey, &config)
		return config, err
	}
}

func (e *Engine) SetConfig(extra string) error {
	e.Config, _ = e.getConfig()
	if e.Config == nil {
		e.Config = make(map[string]string)
	}

	fmt.Println("Setting configuration")
	e.readInput("db.hostname", e.Config)
	e.readInput("db.port", e.Config)
	e.readInput("db.username", e.Config)
	e.readInput("db.password", e.Config)
	e.readInput("db.database", e.Config)

	if len(extra) > 0 {
		arr := strings.Fields(extra)
		for _, k := range arr {
			e.readInput(k, e.Config)
		}
	}
	err := crypto.SaveObjectToEncryptedFile(e.ConfigPath, encKey, e.Config)
	if err == nil {
		fmt.Println("Done")
	} else {
		fmt.Println(err.Error())
	}

	return err
}

func (e *Engine) readInput(key string, config map[string]string) {
	if val, ok := config[key]; ok && len(val) > 0 {
		fmt.Printf("%-16s = (%s) ", key, val)
	} else {
		fmt.Printf("%-16s = ", key)
	}

	reader := bufio.NewReader(os.Stdin)
	newVal, _ := reader.ReadString('\n')
	newVal = strings.TrimSpace(newVal)
	if len(newVal) > 0 {
		r := strings.NewReplacer(`""`, ``, `'`, ``)
		v := r.Replace(newVal)
		if len(v) > 0 {
			config[key] = newVal
		} else {
			config[key] = ``
		}
	}

}

func PrintHelp() {
	fmt.Println(strings.TrimSuffix(filepath.Base(os.Args[0]), filepath.Ext(os.Args[0])))
	CmdFlags.PrintDefaults()
}

func DisplayVersion(prodName, version string) {
	fmt.Printf("%s, v%s\n", prodName, version)
}

func UpdateConfig(section, keyword, value string) error {
	o := orm.NewOrm()
	query := `
		insert into sys_config(section, keyword, value, udate)
		values (?, ?, ?, now())
		on duplicate key update value = values(value), udate = values(udate)
	`
	_, err := o.Raw(query, section, keyword, value).Exec()

	return err
}
