// +build js nacl plan9 windows

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	var conf_file string
	var version bool

	// Parse args
	flag.StringVar(&conf_file, "c", "/etc/molly.conf", "Path to config file")
	flag.BoolVar(&version, "v", false, "Print version and exit")
	flag.Parse()

	// If requested, print version and exit
	if version {
		fmt.Println("Molly Brown version", VERSION)
		os.Exit(0)
	}

	// Read config
	sysConfig, userConfig, err := getConfig(conf_file)
	if err != nil {
		log.Fatal(err)
	}

	// Run server and exit
	var dummy userInfo
	os.Exit(launch(sysConfig, userConfig, dummy))
}
