package main

import (
	"github.com/devplayg/mserver"
	//"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	//"net/http"
	"github.com/devplayg/mserver/loghandler"
	_ "net/http/pprof"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	AppName    = "loghandler"
	AppVersion = "1.0"
)

func main() {
	var (
		version   = mserver.CmdFlags.Bool("version", false, "Version")
		debug     = mserver.CmdFlags.Bool("debug", false, "Debug")
		cpu       = mserver.CmdFlags.Int("cpu", 2, "CPU Count")
		verbose   = mserver.CmdFlags.Bool("v", false, "Verbose")
		setConfig = mserver.CmdFlags.Bool("config", false, "Edit configurations")
		interval  = mserver.CmdFlags.Int64("i", 15000, "Interval(ms)")
		manual    = mserver.CmdFlags.String("manual", "", "StartDate,EndDate,MarkDate")
	)
	mserver.CmdFlags.Usage = mserver.PrintHelp
	mserver.CmdFlags.Parse(os.Args[1:])

	// Display version
	if *version {
		mserver.DisplayVersion(AppName, AppVersion)
		return
	}

	// Set configurations
	engine := mserver.NewEngine(AppName, *debug, *cpu, *interval, *verbose)
	if *setConfig {
		engine.SetConfig("server.addr")
		return
	}
	// Start engine
	if err := engine.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Debug("engine started")

	if len(*manual) > 0 { // Manual(Previous day(s)
		fileLog := loghandler.NewFileLogHandler(engine, nil)
		date, c, err := getManualDate(*manual)
		if err != nil {
			log.Error(err)
			return
		}

		if c == 1 {
			fileLog.RemoveOldStats(date)
		} else if c == 3 {
			fileLog.RemoveSpecificStats(date.Mark)
		}

		log.Debugf("Start calulating statistics (%s ~ %s, Mark as %s)", date.From, date.To, date.Mark)
		wg := new(sync.WaitGroup)

		// Command generation of statistics
		wg.Add(1)
		fileLog.Start(date, wg)

		// Waiting for complete
		wg.Wait()

		// Finish statistics
		log.Debug("End of calulating statistics")

	} else { // Today's statistics
		go func() {
			fileLog := loghandler.NewFileLogHandler(engine, nil)

			for {
				t := time.Now()
				date := &loghandler.StatsDate{
					From: t.Format("2006-01-02") + " 00:00:00",
					To:   t.Format("2006-01-02") + " 23:59:59",
					Mark: t.Format(mserver.DateDefault),
				}

				log.Debugf("Start calulating statistics (%s ~ %s)", date.From, date.To)
				wg := new(sync.WaitGroup)

				// Command generation of statistics
				wg.Add(1)
				fileLog.Start(date, wg)

				// Waiting for complete
				wg.Wait()

				// Finish statistics
				log.Debug("End of calculating statistics")

				// - Update time
				err := mserver.UpdateConfig("stats", "last_update", date.Mark)
				if err != nil {
					log.Error(err)
				}

				// Remove previous statistics
				err = fileLog.RemoveJustBeforeStats()
				if err != nil {
					log.Error(err)
				}

				// Sleep
				log.Debugf("Sleep %3.1fs", (time.Duration(engine.Interval) * time.Millisecond).Seconds())
				time.Sleep(time.Duration(engine.Interval) * time.Millisecond)
			}

		}()
		//go http.ListenAndServe(engine.Config["server.addr"], router)
		//log.Debugf("HTTP server started. Listen: %s", engine.Config["server.addr"])
		//
		// Wait for signal
		log.Debug("Waiting for signal..")
		mserver.WaitForSignals()

	}
}

func getManualDate(str string) (*loghandler.StatsDate, int, error) {
	date := loghandler.StatsDate{}

	parsed := strings.Split(str, ",")
	if len(parsed) == 1 {
		t, err := time.Parse("2006-01-02", parsed[0])
		log.Debug(t)
		if err != nil {
			return nil, len(parsed), err
		}
		date.From = t.Format("2006-01-02") + " 00:00:00"
		date.To = t.Format("2006-01-02") + " 23:59:59"
		date.Mark = t.Format("2006-01-02") + " 00:00:00"
	} else if len(parsed) == 3 {
		dateFrom, err := time.Parse("2006-01-02", parsed[0])
		if err != nil {
			return nil, len(parsed), err
		}
		dateTo, err := time.Parse("2006-01-02", parsed[1])
		if err != nil {
			return nil, len(parsed), err
		}
		dateMark, err := time.Parse(mserver.DateDefault, parsed[2])
		if err != nil {
			return nil, len(parsed), err
		}
		date.From = dateFrom.Format("2006-01-02") + " 00:00:00"
		date.To = dateTo.Format("2006-01-02") + " 23:59:59"
		date.Mark = dateMark.Format(mserver.DateDefault)
	}

	return &date, len(parsed), nil
}

//
//func startLogHandler(handler loghandler.LogHandler) error {
//	if err := handler.Start(); err != nil {
//		return err
//	}
//	log.Infof("Statistics(%s) started", handler.GetName())
//	return nil
//}
