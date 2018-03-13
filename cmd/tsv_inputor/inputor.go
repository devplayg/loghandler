package main

import (
	"github.com/devplayg/mserver"
	"github.com/devplayg/mserver/tsvinputor"
	log "github.com/sirupsen/logrus"
	"os"
)

const (
	AppName    = "M-Server TSV Data Inputor"
	AppVersion = "1.0.1802.10401"
)

func main() {
	var (
		version   = mserver.CmdFlags.Bool("version", false, "Version")
		debug     = mserver.CmdFlags.Bool("debug", false, "Debug")
		cpu       = mserver.CmdFlags.Int("cpu", 2, "CPU Count")
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
		engine.SetConfig("storage.watchDir")
		return
	}
	// Start engine
	if err := engine.Start(); err != nil {
		log.Error(err)
		return
	}
	log.Debug(engine.Config)

	// Start application
	app := tsvinputor.NewInputor(engine)
	app.Start()

	// Wait for signal
	mserver.WaitForSignals()
}
