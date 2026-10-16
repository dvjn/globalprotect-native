package main

import (
	"os"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPeerGroupsMatchesOwnGroups(t *testing.T) {
	sockets, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(sockets[0])
	defer unix.Close(sockets[1])

	groups, err := peerGroups(sockets[0])
	if err != nil {
		t.Fatal(err)
	}
	own, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, gid := range own {
		if !slices.Contains(groups, uint32(gid)) {
			t.Errorf("peer groups %v lack own group %d", groups, gid)
		}
	}
	if len(groups) != len(own) {
		t.Errorf("peer groups %v, own groups %v", groups, own)
	}
}

func TestProcessHomeReadsOwnEnvironment(t *testing.T) {
	if home, want := processHome(int32(os.Getpid())), os.Getenv("HOME"); home != want {
		t.Errorf("processHome = %q, want %q", home, want)
	}
}
