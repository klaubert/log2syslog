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
	//"log/syslog"

	"github.com/BurntSushi/toml"
	syslog "github.com/RackSec/srslog"
	"github.com/asaskevich/govalidator"
	"github.com/hpcloud/tail"
)

//VERSION of log2syslog
const VERSION string = "0.9"
const batch string = "batch"
const file string = "file"

type eventIndex struct {
	fileName string
	length   int
	hash     string
}

type config struct {
	syslogServer syslogServer
	logSources   logSources
	general      general
}

type syslogServer struct {
	Host     string `toml:"host"`
	port     int    `toml:"port"`
	protocol string `toml:"protocol"`
	Format   string `toml:"message_format"`
}

type logSources struct {
	logFiles []string `toml:"log_files"`
	inotity  bool     `toml:"inotify"`
}

type general struct {
	Mode           string `toml:"mode"`
	OffsetFile     string `toml:"offset_file"`
	LogType        string `toml:"log_type"`
	LogFile        string `toml:"log_file"`
	MaxConcurrency int    `toml:"max_concurrency"`
}

// Global vars/Handlers
var conf config
var syslogHandler *syslog.Writer
var logFile *os.File

func logRead(wg *sync.WaitGroup, logFile string, logLineChannel chan<- string) {
	defer wg.Done()
	var seek tail.SeekInfo
	seek.Offset = 0
	followTail := true

	if conf.general.Mode == batch {
		storedOffset, _ := ioutil.ReadFile(conf.general.OffsetFile)
		fileInfo, _ := os.Stat(logFile)
		fileSize := fileInfo.Size()

		followTail = false
		// Seek position from a past execution
		offset, _ := strconv.ParseInt(string(storedOffset), 10, 32)
		if offset > fileSize {
			offset = 0
		}
		seek.Offset = offset
	}

	t, err := tail.TailFile(logFile, tail.Config{
		Follow:    followTail,
		ReOpen:    followTail,
		Location:  &seek,
		MustExist: true,
		Poll:      conf.logSources.inotity,
		Logger:    tail.DiscardingLogger,
	})

	if err != nil {
		log.Printf("Error on follow de index file: %s.\n", err)
	}

	for line := range t.Lines {
		logLineChannel <- line.Text
	}
	if conf.general.Mode == batch {
		fileInfo, _ := os.Stat(logFile)
		fileSize := fileInfo.Size()
		err := ioutil.WriteFile(conf.general.OffsetFile, []byte(strconv.FormatInt(fileSize, 10)), 0640)
		if err != nil {
			log.Printf("Error to write offset file: %s.\n", err)
		}
	}
	close(logLineChannel)
}

func logPump(wg *sync.WaitGroup, logLineChannel <-chan string, statsChannel chan<- string) {
	defer wg.Done()
	for v := range logLineChannel {
		//send log to remote syslog
		log.Println(v)
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
		fmt.Printf(" Check config file %s configuration and syntaxe, something wrong there!", configFile)
		errHappen = true
	}

	// Validate config file
	if !govalidator.StringLength(conf.syslogServer.Host, "1", "120") || !govalidator.IsHost(conf.syslogServer.Host) {
		fmt.Printf(" Syslog Host must be present, it must be an IP Address or hostname (%s).\n", conf.syslogServer.Host)
		errHappen = true
	}
	if !govalidator.InRange(float64(conf.syslogServer.port), 1, 65535) {
		fmt.Printf(" Syslog port must be an integer from 1 to 65535 (%d).\n", conf.syslogServer.port)
		errHappen = true
	}

	if regexp.MustCompile(`^(udp|tcp)$`).MatchString(conf.syslogServer.protocol) == false {
		fmt.Printf(" Protocol must be udp or tcp (%s).\n", conf.syslogServer.protocol)
		errHappen = true
	}

	// _, err = os.Stat(conf.Logsource.logFile)
	// if err != nil {
	// 	fmt.Printf(" Index file %s does not exist, check index_file in %s\n", conf.Logsource.logFile, configFile)
	// 	errHappen = true
	// }

	if conf.general.LogType != file && conf.general.LogType != "syslog" && conf.general.LogType != "stdout" {
		fmt.Printf(" Log Type (log_type) must be either: 'file', 'syslog' or 'stdout'. \n The stdout is the default and will print the log on standard output - your screen,\n check config file (%s).\n", configFile)
		errHappen = true
	}

	if conf.general.LogType == file {
		_, err := os.Stat(conf.general.LogFile)
		if err != nil {
			err := ioutil.WriteFile(conf.general.LogFile, []byte("Start"), 0640)
			if err != nil {
				fmt.Printf(" Impossible to write the log file %s, check file permission.\n", conf.general.LogFile)
				errHappen = true
			}
		}
	}

	if regexp.MustCompile(`^(tail|batch)$`).MatchString(conf.general.Mode) == false {
		fmt.Printf(" Mode must be 'tail' or 'batch'.\n")
		errHappen = true
	}
	if conf.general.Mode == "batch" {
		_, err := os.Stat(conf.general.OffsetFile)
		if err != nil {
			err := ioutil.WriteFile(conf.general.OffsetFile, []byte(strconv.FormatInt(0, 10)), 0640)
			if err != nil {
				fmt.Printf(" Impossible to write offset file %s, check permission.\n", conf.general.OffsetFile)
				errHappen = true
			}
		}
	}

	if errHappen {
		return errors.New(" configuration errors, correct config file and try again")
	}
	return nil
}

func syslogInit() {
	// init of syslog
	var err error
	syslogHandler, err = syslog.Dial(conf.syslogServer.protocol, conf.syslogServer.Host+":"+strconv.Itoa(conf.syslogServer.port), syslog.LOG_INFO|syslog.LOG_DAEMON, "log2syslog")
	if err != nil {
		log.Fatal(err)
	}
	switch conf.syslogServer.Format {
	case "RFC3164":
		formater := syslog.Formatter(syslog.RFC3164Formatter)
		syslogHandler.SetFormatter(formater)
	case "RFC5424":
		formater := syslog.Formatter(syslog.RFC5424Formatter)
		syslogHandler.SetFormatter(formater)
	default:
		formater := syslog.Formatter(syslog.DefaultFormatter)
		syslogHandler.SetFormatter(formater)
	}

	log.SetOutput(syslogHandler)
	log.SetFlags(0)

	log.Println("Log for log2syslog initialized")
}

func localLogInit() {
	if conf.general.LogType == file {
		// init of log to file
		var err error
		logFile, err = os.OpenFile(conf.general.LogFile, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0660)
		if err != nil {
			fmt.Printf("Error opening file: %v", err)
		}

		log.SetOutput(logFile)
		log.SetFlags(3)
	} else if conf.general.LogType == "syslog" {
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

	// startTime := time.Now()

	channelBufferSize := 5
	logLineChannel, statChannel := make(chan string, channelBufferSize), make(chan string, channelBufferSize)

	var wg sync.WaitGroup

	for _, v := range conf.logSources.logFiles {
		wg.Add(1)
		go logRead(&wg, v, logLineChannel)
	}

	// start log pump
	wg.Add(1)
	go logPump(&wg, logLineChannel, statChannel)

	// wait goroutines to finish
	wg.Wait()
	// close log file
	if conf.general.LogType == file {
		logFile.Close()
	}
}
