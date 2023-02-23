// +build linux,go1.16 aix darwin dragonfly freebsd illumos netbsd openbsd solaris

package main

import (
	"log"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

type userInfo struct {
	uid int
	euid int
	gid int
	egid int
	supp_groups []int
	is_setuid bool
	is_setgid bool
	root_user bool
	root_prim_group bool
	root_supp_group bool
	need_drop bool
	unpriv_uid int
	unpriv_gid int
}

func getUserInfo(unprivUser string) (userInfo, error) {
	var ui userInfo
	ui.uid = os.Getuid()
	ui.euid = os.Geteuid()
	ui.gid = os.Getgid()
	ui.egid = os.Getegid()
	supp_groups, err := os.Getgroups()
	if err != nil {
		log.Println("Could not get supplementary groups: ", err.Error())
		return ui, err
	}
	ui.supp_groups = supp_groups
	ui.unpriv_uid = -1
	ui.unpriv_gid = -1

	ui.is_setuid = ui.uid != ui.euid
	ui.is_setgid = ui.gid != ui.egid
	ui.root_user = ui.uid == 0 || ui.euid == 0
	ui.root_prim_group = ui.gid == 0 || ui.egid == 0
	for _, gid := range ui.supp_groups {
		if gid == 0 {
			ui.root_supp_group = true
			break
		}
	}
	ui.need_drop = ui.is_setuid || ui.is_setgid || ui.root_user || ui.root_prim_group || ui.root_supp_group

	if ui.root_user || ui.root_prim_group {
		nobody_user, err := user.Lookup(unprivUser)
		if err != nil {
			log.Println("Running as root but could not lookup UID for user " + unprivUser + ": " + err.Error())
			return ui, err
		}
		ui.unpriv_uid, err = strconv.Atoi(nobody_user.Uid)
		ui.unpriv_gid, err = strconv.Atoi(nobody_user.Gid)
		if err != nil {
			log.Println("Running as root but could not lookup UID for user " + unprivUser + ": " + err.Error())
			return ui, err
		}
	}

	return ui, nil
}
func DropPrivs(ui userInfo) error {

	// If we're already unprivileged, all good
	if !ui.need_drop {
		return nil
	}

	// Drop supplementary groups
	if ui.root_supp_goup {
		err := syscall.Setgroups([]int{})
		if err != nil {
			log.Println("Could not unset supplementary groups: " + err.Error())
			return err
		}
	}

	// Setgid()
	if ui.root_prim_group || ui.is_setgid {
		var target_gid int
		if ui.root_prim_group {
			target_gid = ui.unpriv_gid
		} else {
			target_gid = ui.gid
		}
		err := syscall.Setgid(target_gid)
		if err != nil {
			log.Println("Could not setgid to " + strconv.Itoa(target_gid) + ": " + err.Error())
			return err
		}
	}

	// Setuid()
	if ui.root_user || ui.is_setuid {
		var target_uid int
		if ui.root_user {
			target_uid = ui.unpriv_uid
		} else {
			target_uid = ui.uid
		}
		err := syscall.Setuid(target_uid)
		if err != nil {
			log.Println("Could not setuid to " + strconv.Itoa(target_uid) + ": " + err.Error())
			return err
		}
	}

	return nil
}
