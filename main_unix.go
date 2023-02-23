// +build aix darwin dragonfly freebsd illumos linux netbsd openbsd solaris

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"
)

func main() {
	var conf_file string
	var chroot string
	var user string
	var version bool

	// Parse args
	flag.StringVar(&conf_file, "c", "/etc/molly.conf", "Path to config file")
	flag.StringVar(&chroot, "C", "", "Path to chroot into")
	flag.StringVar(&user, "u", "nobody", "Unprivileged user")
	flag.BoolVar(&version, "v", false, "Print version and exit")
	flag.Parse()

	// If requested, print version and exit
	if version {
		fmt.Println("Molly Brown version", VERSION)
		os.Exit(0)
	}

	// Read config
	config, err := getConfig(conf_file)
	if err != nil {
		log.Fatal(err)
	}

	// Read user info
	privInfo, err := getUserInfo(user)

	// Chroot, if asked
	if chroot != "" {
		err := syscall.Chroot(chroot)
		if err == nil {
			err = os.Chdir("/")
		}
		if err != nil {
			log.Println("Could not chroot to " + chroot + ": " + err.Error())
			os.Exit(1)
		}
	}

	// Run server and exit
	os.Exit(launch(config, privInfo))
}
