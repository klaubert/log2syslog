package main

import (
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	//"log/syslog"
	"github.com/BurntSushi/toml"
	syslog "github.com/RackSec/srslog"
	"github.com/asaskevich/govalidator"
	"github.com/hpcloud/tail"
	"github.com/juju/ratelimit"
)

//VERSION of log2syslog
const VERSION string = "0.9"
const file string = "file"

type eventIndex struct {
	fileName string
	length   int
	hash     string
}

type config struct {
	SyslogServer syslogServer `toml:"Syslog_server"`
	Logsources   logSources
	General      general
}

type syslogServer struct {
	Host     string `toml:"host"`
	Port     int    `toml:"port"`
	Protocol string `toml:"protocol"`
	Format   string `toml:"message_format"`
	LogTag   string `toml:"log_tag"`
}

type logSources struct {
	LogFiles []string `toml:"log_files"`
	inotity  bool     `toml:"inotify"`
}

type general struct {
	Rate                int    `toml:"rate_limit"`
	LogType             string `toml:"log_type"`
	LogFile             string `toml:"log_file"`
	MaxConcurrency      int    `toml:"max_concurrency"`
	ReplaceControlChars bool   `toml:"replace_control_characters"`
}

// Counters hold the stats structure used to increment counters
type Counters struct {
	Read int64
	Sent int64
}

// Global vars/Handlers
var conf config
var syslogHandler *syslog.Writer
var logFile *os.File

// Stats is channel used to receive stats from processing go routines
var Stats = make(chan Counters, 100)
var readLogCnt, sentLogCnt int64

// CounterStats read and publish stats from event insert
func CounterStats() {
	for {
		select {
		case c := <-Stats:
			if c.Read != 0 {
				atomic.AddInt64(&readLogCnt, c.Read)
			}
			if c.Sent != 0 {
				atomic.AddInt64(&sentLogCnt, c.Sent)
			}
		}
	}
}

// PrintStats print the stats on defaul log writer each minute
func PrintStats() {
	var glbRead, glbSent int64

	var currentTime = time.Now()
	var startTime = currentTime.Truncate(time.Minute).Add(time.Minute)
	var duration = startTime.Sub(currentTime)
	heartbeat := time.Tick(duration)

	for {
		select {
		case <-heartbeat:
			heartbeat = time.Tick(60 * time.Second)

			// publish stats at a fixed interval
			readPartial := atomic.LoadInt64(&readLogCnt)
			atomic.StoreInt64(&readLogCnt, 0)

			sentPartial := atomic.LoadInt64(&sentLogCnt)
			atomic.StoreInt64(&sentLogCnt, 0)

			glbRead = glbRead + readPartial
			glbSent = glbSent + sentPartial
			log.Printf("Readed: Total (from start): %d, Partial: %d/min (avr %d/sec)\n", glbRead, readPartial, readPartial/60)
			log.Printf("Sent: Total (from start): %d, Partial: %d/min (avr %d/sec)\n", glbSent, sentPartial, sentPartial/60)
		}
	}
}

// stripCtlFromBytes convert
func replaceCtlandExtCharbySpace(str string) string {
	b := make([]byte, len(str))
	// fmt.Println("\nLen inicial: " + strconv.Itoa(len(str)))
	var bl int
	for i := 0; i < len(str); i++ {
		c := str[i]
		// fmt.Printf("Char: %d, ASCII: %s \n", c, string(c))
		if c >= 32 && c <= 127 {
			b[bl] = c
			bl++
		} else {
			b[bl] = 32
			bl++
		}

	}
	// fmt.Println("\nLen Final: " + strconv.Itoa(len(b)))
	return string(b[:bl])
}

func logRead(wg *sync.WaitGroup, logFile string, logLineChannel chan<- string, st chan<- Counters) {
	defer wg.Done()
	var seek tail.SeekInfo
	// seek.Offset = fileInfo.Size()
	followTail := true

	t, err := tail.TailFile(logFile, tail.Config{
		Follow:    followTail,
		ReOpen:    followTail,
		Location:  &seek,
		MustExist: true,
		Poll:      conf.Logsources.inotity,
		Logger:    tail.DiscardingLogger,
	})

	if err != nil {
		log.Printf("Error on follow de index file: %s.\n", err)
	}
	var c Counters

	for line := range t.Lines {
		if conf.General.ReplaceControlChars {
			logLineChannel <- replaceCtlandExtCharbySpace(line.Text)
		} else {
			logLineChannel <- line.Text
		}

		c.Read = 1
		st <- c
	}
}

func logPump(wg *sync.WaitGroup, logLineChannel <-chan string, st chan<- Counters, rate int) {
	defer wg.Done()
	var c Counters
	mps := ratelimit.NewBucketWithRate(float64(rate), 1)

	for v := range logLineChannel {
		mps.Wait(1)
		fmt.Fprint(syslogHandler, v)
		c.Sent = 1
		st <- c
	}
}

func configInit(configFile string) error {
	var errHappen bool
	_, err := os.Stat(configFile)
	if err != nil {
		fmt.Printf(" Configuration file %s does not exist\n", configFile)
		return err
	}
	_, err = toml.DecodeFile(configFile, &conf)
	if err != nil {
		fmt.Printf(" Check config file %s configuration and syntaxe, something wrong there!\n", configFile)
		fmt.Printf(" Error: %s\n", err)
		errHappen = true
	}

	// Validate config file
	if !govalidator.StringLength(conf.SyslogServer.Host, "1", "120") || !govalidator.IsHost(conf.SyslogServer.Host) {
		fmt.Printf(" Config Error: Syslog Host must be present, it must be an IP Address or hostname (%s).\n", conf.SyslogServer.Host)
		errHappen = true
	}

	if !govalidator.InRangeInt(conf.SyslogServer.Port, 1, 65535) {
		fmt.Printf(" Config Error: Syslog Port must be an integer from 1 to 65535 (%d).\n", conf.SyslogServer.Port)
		errHappen = true
	}

	if !govalidator.InRangeInt(conf.General.Rate, 1, 1000000) {
		fmt.Printf(" Config Error: Rate limit must be an integer from 1 to 1000000 (%d).\n", conf.General.Rate)
		errHappen = true
	}

	if regexp.MustCompile(`^(udp|tcp)$`).MatchString(conf.SyslogServer.Protocol) == false {
		fmt.Printf(" Config Error: Protocol must be udp or tcp (%s).\n", conf.SyslogServer.Protocol)
		errHappen = true
	}

	for _, v := range conf.Logsources.LogFiles {
		_, err = os.Stat(v)
		if err != nil {
			fmt.Printf(" Config Error: Log file %s does not exist, check it and try again.\n", v)
			errHappen = true
		}
	}

	if conf.General.LogType != file && conf.General.LogType != "syslog" && conf.General.LogType != "stdout" {
		fmt.Printf(" Config Error: Log Type (log_type) must be either: 'file', 'syslog' or 'stdout'. \n The stdout is the default and will print the log on standard output - your screen,\n check config file (%s).\n", configFile)
		errHappen = true
	}

	if conf.General.LogType == file {
		_, err := os.Stat(conf.General.LogFile)
		if err != nil {
			err := ioutil.WriteFile(conf.General.LogFile, []byte("Start"), 0640)
			if err != nil {
				fmt.Printf(" Config Error: Impossible to write the log file %s, check file permission.\n", conf.General.LogFile)
				errHappen = true
			}
		}
	}

	if errHappen {
		return errors.New("Configuration errors, correct config file and try again")
	}
	return nil
}

func syslogInit() {
	// init of syslog
	var err error
	tag := "log2syslog"
	if len(conf.SyslogServer.LogTag) > 0 {
		tag = conf.SyslogServer.LogTag
	}

	syslogHandler, err = syslog.Dial(conf.SyslogServer.Protocol, conf.SyslogServer.Host+":"+strconv.Itoa(conf.SyslogServer.Port), syslog.LOG_INFO|syslog.LOG_DAEMON, tag)
	if err != nil {
		log.Fatal(err)
	}

	switch conf.SyslogServer.Format {
	case "none":
		// no formater
		log.SetOutput(syslogHandler)
	case "RFC3164":
		formater := syslog.Formatter(syslog.RFC3164Formatter)
		syslogHandler.SetFormatter(formater)
		log.SetOutput(syslogHandler)
	case "RFC5424":
		formater := syslog.Formatter(syslog.RFC5424Formatter)
		syslogHandler.SetFormatter(formater)
		log.SetOutput(syslogHandler)
	default:
		formater := syslog.Formatter(syslog.DefaultFormatter)
		syslogHandler.SetFormatter(formater)
		log.SetOutput(syslogHandler)
	}

	log.SetFlags(0)

	//log.Println("Remote log initialized")
}

func localLogInit() {
	if conf.General.LogType == file {
		// init of log to file
		var err error
		logFile, err = os.OpenFile(conf.General.LogFile, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0660)
		if err != nil {
			fmt.Printf("Error opening file: %v", err)
		}

		log.SetOutput(logFile)
		log.SetFlags(3)
	} else if conf.General.LogType == "syslog" {
		log.SetOutput(syslogHandler)
		log.SetFlags(0)
	} else {
		log.SetOutput(os.Stdout)
	}
	log.Println("Log for log2syslog initialized")
}

func main() {

	configFile := flag.String("f", "./log2syslog.conf", "Configuration file")
	flag.Parse()

	// config read and validation
	err := configInit(*configFile)
	if err != nil {
		fmt.Println("\n", err)
		os.Exit(1)
	}

	// initialize syslog Handler
	syslogInit()

	// initialize local log system
	localLogInit()
	go CounterStats()
	go PrintStats()
	// startTime := time.Now()

	channelBufferSize := 5
	logLineChannel := make(chan string, channelBufferSize)

	var wg sync.WaitGroup

	for _, v := range conf.Logsources.LogFiles {
		wg.Add(1)
		go logRead(&wg, v, logLineChannel, Stats)
	}

	// start log pump
	wg.Add(1)
	go logPump(&wg, logLineChannel, Stats, conf.General.Rate)

	// wait goroutines to finish
	wg.Wait()
	// close log file
	if conf.General.LogType == file {
		logFile.Close()
	}
}
