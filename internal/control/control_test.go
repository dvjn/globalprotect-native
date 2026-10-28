package control

import (
	"bufio"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCallRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	t.Setenv("GPN_SOCKET", path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	since := time.Date(2026, 10, 15, 3, 0, 0, 0, time.UTC)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		defer connection.Close()
		request, err := ReadRequest(bufio.NewReader(connection))
		if err != nil || request.Command != CommandLogin || request.Token != "t" {
			WriteResponse(connection, Response{Error: "unexpected request"})
			return
		}
		WriteResponse(connection, Response{Status: &Status{State: StateConnected, Gateway: "India North", Since: since}})
	}()

	response, err := Call(Request{Command: CommandLogin, Username: "alice", Token: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status == nil || response.Status.State != StateConnected || !response.Status.Since.Equal(since) {
		t.Errorf("got %+v", response.Status)
	}
}

func TestReceiveReturnsDaemonError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	t.Setenv("GPN_SOCKET", path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, _ := listener.Accept()
		defer connection.Close()
		ReadRequest(bufio.NewReader(connection))
		WriteResponse(connection, Response{Error: "not allowed"})
	}()

	_, err = Call(Request{Command: CommandStatus})
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("err = %v, want the daemon's error", err)
	}
}

func TestLoginPageSurvivesJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	t.Setenv("GPN_SOCKET", path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	page := []byte("<html><form action=\"https://cloud-auth.example/auth\"></form></html>\n")
	go func() {
		connection, _ := listener.Accept()
		defer connection.Close()
		ReadRequest(bufio.NewReader(connection))
		WriteResponse(connection, Response{LoginPage: page, LoginTimeout: 10 * time.Minute})
	}()

	response, err := Call(Request{Command: CommandPrelogin})
	if err != nil {
		t.Fatal(err)
	}
	if string(response.LoginPage) != string(page) || response.LoginTimeout != 10*time.Minute {
		t.Errorf("got %q, %s", response.LoginPage, response.LoginTimeout)
	}
}

func TestUpdateSurvivesJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control.sock")
	t.Setenv("GPN_SOCKET", path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	update := Update{Available: "0.3.0", Installing: true, Error: "the installer failed"}
	go func() {
		connection, _ := listener.Accept()
		defer connection.Close()
		ReadRequest(bufio.NewReader(connection))
		WriteResponse(connection, Response{Status: &Status{State: StateConnected, Update: update}, Update: "Installing 0.3.0"})
	}()

	response, err := Call(Request{Command: CommandUpdate})
	if err != nil {
		t.Fatal(err)
	}
	if response.Status.Update != update || response.Update != "Installing 0.3.0" {
		t.Errorf("got %+v, %q", response.Status.Update, response.Update)
	}
}
