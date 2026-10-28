package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/state"
)

// runDaemon serves the control socket and owns the tunnel. It runs as root.
func runDaemon(args []string) error {
	flags := flag.NewFlagSet("daemon", flag.ExitOnError)
	loadEnvironment := environmentFlags(flags)
	socketPath := flags.String("socket", control.DefaultSocket, "control socket")
	groupName := flags.String("group", "gpn", "group whose members may control the daemon from any session")
	flags.Parse(args)
	env, envErr := loadEnvironment()
	if envErr != nil {
		fmt.Fprintln(os.Stderr, "Settings are invalid; connecting will fail until they are fixed:", envErr)
	}
	if os.Geteuid() != 0 {
		return errors.New("the daemon manages network devices; run it as root")
	}
	var allowedGroups []uint32
	if group, err := user.LookupGroup(*groupName); err == nil {
		if gid, err := strconv.ParseUint(group.Gid, 10, 32); err == nil {
			allowedGroups = append(allowedGroups, uint32(gid))
		}
	}
	lock, err := lockDaemon()
	if err != nil {
		return err
	}
	defer lock.Close()

	listener, err := listenControl(*socketPath)
	if err != nil {
		return err
	}
	defer os.Remove(*socketPath)
	defer listener.Close()

	server := &daemon{
		loadEnvironment: loadEnvironment,
		allowedGroups:   allowedGroups,
		status:          control.Status{State: control.StateDisconnected, Since: time.Now()},
		watchers:        map[chan control.Status]bool{},
	}
	go server.serve(listener)
	fmt.Fprintf(os.Stderr, "Listening on %s for root, members of %s and polkit action %s.\n", *socketPath, *groupName, controlAction)
	if envErr == nil && env.portalKnown() {
		if userHome, found := takeReconnectMarker(env.statePath); found {
			fmt.Fprintln(os.Stderr, "Connecting again after the update.")
			server.connect(userHome)
		} else if env.settings.AutoConnect {
			fmt.Fprintln(os.Stderr, "Connecting, as auto_connect asks.")
			server.connect("")
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go server.watchUpdates(ctx)
	go func() {
		err := watchResume(ctx, func() {
			if server.restart() {
				fmt.Fprintln(os.Stderr, "Resumed from sleep; rebuilding the tunnel.")
			}
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "Not watching for resume:", err)
		}
	}()
	<-ctx.Done()
	server.rememberTunnel()
	server.disconnect()
	return nil
}

// daemonLockPath is held for as long as a daemon runs. The device, XFRM state and rules have
// fixed names, so a second daemon or a `gpn cleanup` would tear down the first one's tunnel.
const daemonLockPath = "/run/globalprotect-native/daemon.lock"

// errDaemonRunning means another process holds the daemon lock.
var errDaemonRunning = errors.New("a gpn daemon is already running")

// lockDaemon takes the daemon lock; closing the file releases it.
func lockDaemon() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(daemonLockPath), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(daemonLockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errDaemonRunning
		}
		return nil, err
	}
	return file, nil
}

// listenControl opens the socket for every local user; the daemon decides whom to answer.
func listenControl(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	os.Remove(path)
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		listener.Close()
		return nil, err
	}
	return listener, nil
}

type daemon struct {
	// loadEnvironment reads the settings file afresh, so a reconnect applies edits to it.
	loadEnvironment func() (environment, error)
	allowedGroups   []uint32

	lock     sync.Mutex
	status   control.Status
	watchers map[chan control.Status]bool
	// stop cancels the running tunnel and finished closes when it has cleaned up;
	// both are nil while no tunnel runs.
	stop     context.CancelFunc
	finished chan struct{}
	// restartTunnel ends the current attempt so the run loop builds a new tunnel at once.
	restartTunnel context.CancelFunc
	// userHome belongs to the user who last asked to connect.
	userHome string
	// updating is held while an update is checked and downloaded.
	updating sync.Mutex
	releases control.Update
}

func (server *daemon) serve(listener net.Listener) {
	for {
		connection, err := listener.Accept()
		if err != nil {
			return
		}
		go server.handle(connection)
	}
}

func (server *daemon) handle(connection net.Conn) {
	defer connection.Close()
	userHome, err := server.peer(connection)
	if err != nil {
		control.WriteResponse(connection, control.Response{Error: err.Error()})
		return
	}
	request, err := control.ReadRequest(bufio.NewReader(connection))
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	switch request.Command {
	case control.CommandStatus:
		server.respond(connection, nil)
	case control.CommandWatch:
		server.watch(connection)
	case control.CommandConnect:
		if err := server.saveChoice(request.Portal, request.Gateway); err != nil {
			server.respond(connection, err)
			return
		}
		server.respond(connection, server.connect(userHome))
	case control.CommandDisconnect:
		server.disconnect()
		server.respond(connection, nil)
	case control.CommandReconnect:
		if server.restart() {
			server.respond(connection, nil)
		} else {
			server.respond(connection, server.connect(userHome))
		}
	case control.CommandPrelogin:
		if err := server.saveChoice(request.Portal, ""); err != nil {
			control.WriteResponse(connection, control.Response{Error: err.Error()})
			return
		}
		page, timeout, err := server.prelogin(ctx)
		if err != nil {
			control.WriteResponse(connection, control.Response{Error: err.Error()})
			return
		}
		control.WriteResponse(connection, control.Response{LoginPage: page, LoginTimeout: timeout})
	case control.CommandLogin:
		server.respond(connection, server.login(ctx, request.Username, request.Token))
	case control.CommandUpdate:
		message, install, err := server.prepareUpdate()
		if err != nil {
			control.WriteResponse(connection, control.Response{Error: err.Error()})
			return
		}
		control.WriteResponse(connection, control.Response{Update: message})
		if install != nil {
			go install()
		}
	default:
		control.WriteResponse(connection, control.Response{Error: fmt.Sprintf("unknown command %q", request.Command)})
	}
}

// peer identifies the connecting process, refuses anyone but root, the allowed group and
// sessions polkit allows, and returns the process's home directory. It asks the kernel rather
// than the user database, which a static binary can only read from /etc/passwd and /etc/group.
func (server *daemon) peer(connection net.Conn) (string, error) {
	raw, err := connection.(*net.UnixConn).SyscallConn()
	if err != nil {
		return "", err
	}
	var credentials *unix.Ucred
	var groups []uint32
	var credentialsErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, credentialsErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		if credentialsErr == nil {
			groups, credentialsErr = peerGroups(int(fd))
		}
	}); err != nil {
		return "", err
	}
	if credentialsErr != nil {
		return "", credentialsErr
	}
	groups = append(groups, credentials.Gid)

	userHome := processHome(credentials.Pid)
	if credentials.Uid == 0 || slices.ContainsFunc(groups, func(gid uint32) bool { return slices.Contains(server.allowedGroups, gid) }) {
		return userHome, nil
	}
	allowed, err := polkitAllows(credentials.Pid, credentials.Uid)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Authorization check failed:", err)
	}
	if !allowed {
		return "", errors.New("you may not control the VPN from this session; use an active desktop session or join the gpn group")
	}
	return userHome, nil
}

// peerGroups is the connecting process's supplementary groups from SO_PEERGROUPS, see socket(7).
// The kernel answers ERANGE with the size it needs when the buffer is too small.
func peerGroups(fd int) ([]uint32, error) {
	groups := make([]uint32, 64)
	for {
		size := uint32(len(groups) * 4)
		_, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_SOCKET, unix.SO_PEERGROUPS,
			uintptr(unsafe.Pointer(&groups[0])), uintptr(unsafe.Pointer(&size)), 0)
		switch errno {
		case 0:
			return groups[:size/4], nil
		case unix.ERANGE:
			groups = make([]uint32, size/4)
		default:
			return nil, errno
		}
	}
}

// processHome is HOME from the environment of process pid, or "" when it has none.
func processHome(pid int32) string {
	environment, err := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	if err != nil {
		return ""
	}
	for variable := range bytes.SplitSeq(environment, []byte{0}) {
		if home, found := bytes.CutPrefix(variable, []byte("HOME=")); found {
			return string(home)
		}
	}
	return ""
}

func (server *daemon) respond(connection net.Conn, err error) {
	response := control.Response{Status: new(control.Status)}
	if err != nil {
		response.Error = err.Error()
	}
	server.lock.Lock()
	*response.Status = server.status
	server.lock.Unlock()
	control.WriteResponse(connection, response)
}

// watch streams every status change until the client goes away.
func (server *daemon) watch(connection net.Conn) {
	updates := make(chan control.Status, 8)
	server.lock.Lock()
	server.watchers[updates] = true
	current := server.status
	server.lock.Unlock()
	defer func() {
		server.lock.Lock()
		delete(server.watchers, updates)
		server.lock.Unlock()
	}()

	gone := make(chan struct{})
	go func() {
		bufio.NewReader(connection).ReadByte()
		close(gone)
	}()

	for status := current; ; {
		if control.WriteResponse(connection, control.Response{Status: &status}) != nil {
			return
		}
		select {
		case status = <-updates:
		case <-gone:
			return
		}
	}
}

func (server *daemon) setStatus(status control.Status) {
	server.lock.Lock()
	defer server.lock.Unlock()
	server.setStatusLocked(status)
}

func (server *daemon) setStatusLocked(status control.Status) {
	status.Since = time.Now()
	status.Update = server.releases
	server.status = status
	server.broadcastLocked()
}

// changeReleases changes what the status says about updates.
func (server *daemon) changeReleases(change func(*control.Update)) {
	server.lock.Lock()
	defer server.lock.Unlock()
	before := server.releases
	change(&server.releases)
	if server.releases == before {
		return
	}
	server.status.Update = server.releases
	server.broadcastLocked()
}

func (server *daemon) broadcastLocked() {
	status := server.status
	for updates := range server.watchers {
		select {
		case updates <- status:
		default:
		}
	}
}

// connect starts the tunnel unless one already runs.
func (server *daemon) connect(userHome string) error {
	server.lock.Lock()
	defer server.lock.Unlock()
	if server.stop != nil {
		return nil
	}

	ctx, stop := context.WithCancel(context.Background())
	finished := make(chan struct{})
	server.stop, server.finished, server.userHome = stop, finished, userHome
	server.setStatusLocked(control.Status{State: control.StateConnecting})
	go server.run(ctx, finished, userHome)
	return nil
}

// reconnectDelays are the waits between failed attempts; the last one repeats.
var reconnectDelays = []time.Duration{2 * time.Second, 5 * time.Second, 10 * time.Second, 30 * time.Second, time.Minute}

// stableAfter is how long a tunnel has to hold before a later failure starts the delays over.
const stableAfter = time.Minute

// run keeps a tunnel up until ctx ends or the portal wants a new login. A tunnel that fails is
// built again after a delay; one that needs rebuilding (rekey, network change, resume) at once.
func (server *daemon) run(ctx context.Context, finished chan struct{}, userHome string) {
	final := control.Status{State: control.StateDisconnected}
	defer func() {
		server.lock.Lock()
		defer server.lock.Unlock()
		server.stop, server.finished, server.restartTunnel = nil, nil, nil
		close(finished)
		server.setStatusLocked(final)
	}()

	failures := 0
	for {
		attempt, restart := context.WithCancel(ctx)
		server.lock.Lock()
		server.restartTunnel = restart
		server.lock.Unlock()

		env, err := server.loadEnvironment()
		if err != nil {
			restart()
			final = control.Status{State: control.StateFailed, Error: err.Error()}
			return
		}
		var connectedAt time.Time
		err = runTunnel(attempt, env, tunnelOptions{
			userHome: userHome,
			onConnected: func(status control.Status) {
				connectedAt = time.Now()
				server.setStatus(status)
			},
		})
		restart()

		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, gp.ErrAuthenticationRejected):
			final = control.Status{State: control.StateNeedsLogin, Error: err.Error()}
			return
		case errors.Is(err, errNotConfigured):
			final = control.Status{State: control.StateFailed, Error: err.Error()}
			return
		}

		if !connectedAt.IsZero() && time.Since(connectedAt) > stableAfter {
			failures = 0
		}
		var delay time.Duration
		reason := "restart requested"
		if err != nil {
			reason = err.Error()
			if !needsRebuild(err) {
				delay = reconnectDelays[min(failures, len(reconnectDelays)-1)]
				failures++
			}
		}
		fmt.Fprintf(os.Stderr, "Reconnecting in %s: %s\n", delay, reason)
		server.setStatus(control.Status{State: control.StateReconnecting, Error: reason})

		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// restart rebuilds a running tunnel at once, as after resume. It reports whether one was running.
func (server *daemon) restart() bool {
	server.lock.Lock()
	defer server.lock.Unlock()
	if server.restartTunnel == nil {
		return false
	}
	server.restartTunnel()
	server.setStatusLocked(control.Status{State: control.StateReconnecting, Error: "restart requested"})
	return true
}

// disconnect stops the tunnel and waits until it has cleaned up.
func (server *daemon) disconnect() {
	server.lock.Lock()
	stop, finished := server.stop, server.finished
	server.lock.Unlock()
	if stop == nil {
		return
	}
	stop()
	<-finished
}

func (server *daemon) saveChoice(portal, gateway string) error {
	env, err := server.loadEnvironment()
	if err != nil {
		return err
	}
	return env.saveChoice(portal, gateway)
}

// prelogin returns the portal's SAML page for the client to open in a browser.
func (server *daemon) prelogin(ctx context.Context) ([]byte, time.Duration, error) {
	env, err := server.loadEnvironment()
	if err != nil {
		return nil, 0, err
	}
	portal, _, err := env.portalClient()
	if err != nil {
		return nil, 0, err
	}
	prelogin, err := portal.PortalPrelogin(ctx)
	if err != nil {
		return nil, 0, err
	}
	if !prelogin.UsesCAS() {
		return nil, 0, errors.New("portal does not use Cloud Authentication; only CAS login is supported")
	}
	page, err := prelogin.LoginPage()
	return page, prelogin.LoginTimeout(), err
}

// login exchanges the browser's token for a portal cookie and saves it. A tunnel that stopped
// because it needed a login starts again.
func (server *daemon) login(ctx context.Context, username, token string) error {
	env, err := server.loadEnvironment()
	if err != nil {
		return err
	}
	portal, saved, err := env.portalClient()
	if err != nil {
		return err
	}
	portalConfig, _, err := portal.PortalGetConfig(ctx, gp.Credential{Username: username, Token: token})
	if err != nil {
		return err
	}
	saved.Portals[portal.Server] = state.PortalCookie{
		Username:               username,
		UserAuthCookie:         portalConfig.UserAuthCookie,
		PrelogonUserAuthCookie: portalConfig.PrelogonUserAuthCookie,
		SavedAt:                time.Now(),
	}
	if err := saved.Save(env.statePath); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Logged in to %s as %s.\n", portal.Server, username)

	server.lock.Lock()
	resume := server.status.State == control.StateNeedsLogin
	userHome := server.userHome
	server.lock.Unlock()
	if resume {
		return server.connect(userHome)
	}
	return nil
}
