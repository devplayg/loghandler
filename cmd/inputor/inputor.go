package main

import (
	"github.com/devplayg/mserver"
	log "github.com/sirupsen/logrus"
	"os"
	"github.com/devplayg/mserver/inputor"
	"github.com/oschwald/geoip2-golang"
	"path/filepath"
)

const (
	AppName    = "M-Server Log Inputor"
	AppVersion = "1.0.1803.10801"
)

func main() {
	var (
		version   = mserver.CmdFlags.Bool("version", false, "Version")
		debug     = mserver.CmdFlags.Bool("debug", false, "Debug")
		cpu       = mserver.CmdFlags.Int("cpu", 3, "CPU Count")
		verbose   = mserver.CmdFlags.Bool("v", false, "Verbose")
		setConfig = mserver.CmdFlags.Bool("config", false, "Edit configurations")
		interval  = mserver.CmdFlags.Int64("i", 5000, "Interval(ms)")
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
		engine.SetConfig("dir.filetrans ext.filetrans dir.detection ext.detection dir.traffic ext.traffic")
		return
	}
	// Start engine
	if err := engine.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Debug(engine.Config)

	// Load "GeoIP2 Lite"

	geoIpPath, _ := filepath.Abs(os.Args[0])
	geoIpPath = filepath.Join(filepath.Dir(geoIpPath), "GeoLite2-Country.mmdb")
	log.Debug(geoIpPath)
	ipDB, err := geoip2.Open(geoIpPath)
	if err != nil  {
		log.Error(err)
		return
	}
	defer func() {
		if ipDB != nil {
			ipDB.Close()
		}
	}()

	// Start application
	app := inputor.NewInputor(engine, ipDB)
	errChan := make(chan error)
	app.StartFiletransInputor(errChan)
	go logDrain(errChan)

	// Wait for signal
	mserver.WaitForSignals()
}

func logDrain(errChan <-chan error) {
	for {
		select {
		case err := <-errChan:
			if err != nil {
				log.Error(err)
			}
		}
	}
}
