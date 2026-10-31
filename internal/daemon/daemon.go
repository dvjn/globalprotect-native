package daemon

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/dvjn/globalprotect-native/internal/config"
	"github.com/dvjn/globalprotect-native/internal/control"
	"github.com/dvjn/globalprotect-native/internal/engine"
	"github.com/dvjn/globalprotect-native/internal/platform/linux"
	"github.com/dvjn/globalprotect-native/internal/profile"
)

// Options are what the daemon runs with.
type Options struct {
	// Socket is the control socket's path.
	Socket string
	// Group's members may control the daemon from any session.
	Group string
	// LoadProfile reads the settings and state afresh, so a reconnect applies edits to them.
	LoadProfile func() (profile.Profile, error)
	// Version is this build's, which updates are compared against.
	Version string
	// Log receives the tunnel's progress.
	Log *log.Logger
}

// Run serves the control socket and owns the tunnel until ctx ends. It runs as root.
func Run(ctx context.Context, options Options) error {
	profile, profileErr := options.LoadProfile()
	if profileErr != nil {
		fmt.Fprintln(os.Stderr, "Settings are invalid; connecting will fail until they are fixed:", profileErr)
	}
	if os.Geteuid() != 0 {
		return errors.New("the daemon manages network devices; run it as root")
	}
	var allowedGroups []uint32
	if group, err := user.LookupGroup(options.Group); err == nil {
		if gid, err := strconv.ParseUint(group.Gid, 10, 32); err == nil {
			allowedGroups = append(allowedGroups, uint32(gid))
		}
	}
	lock, err := Lock()
	if err != nil {
		return err
	}
	defer lock.Close()

	listener, err := listenControl(options.Socket)
	if err != nil {
		return err
	}
	defer os.Remove(options.Socket)
	defer listener.Close()

	server := &daemon{
		loadProfile:   options.LoadProfile,
		version:       options.Version,
		log:           options.Log,
		allowedGroups: allowedGroups,
		status:        control.Status{State: control.StateDisconnected, Since: time.Now()},
		watchers:      map[chan control.Status]bool{},
	}
	go server.serve(listener)
	fmt.Fprintf(os.Stderr, "Listening on %s for root, members of %s and polkit action %s.\n", options.Socket, options.Group, controlAction)
	if profileErr == nil && profile.PortalKnown() {
		if userHome, found := takeReconnectMarker(profile.StatePath); found {
			fmt.Fprintln(os.Stderr, "Connecting again after the update.")
			server.connect(userHome)
		} else if profile.Settings.AutoConnect {
			fmt.Fprintln(os.Stderr, "Connecting, as auto_connect asks.")
			server.connect("")
		}
	}

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

// lockPath is held for as long as a daemon runs. The device, XFRM state and rules have
// fixed names, so a second daemon or a `gpn cleanup` would tear down the first one's tunnel.
const lockPath = "/run/globalprotect-native/daemon.lock"

// ErrRunning means another process holds the daemon lock.
var ErrRunning = errors.New("a gpn daemon is already running")

// Lock takes the daemon lock, which keeps a second daemon or a cleanup from tearing down the
// tunnel of a running one; closing the file releases it.
func Lock() (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		file.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrRunning
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
	// loadProfile reads the settings file afresh, so a reconnect applies edits to it.
	loadProfile   func() (profile.Profile, error)
	version       string
	log           *log.Logger
	allowedGroups []uint32

	lock     sync.Mutex
	status   control.Status
	watchers map[chan control.Status]bool
	// stop cancels the running tunnel and finished closes when it has cleaned up;
	// both are nil while no tunnel runs.
	stop     context.CancelFunc
	finished chan struct{}
	// supervisor keeps the running tunnel up.
	supervisor *engine.Supervisor
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
	supervisor := &engine.Supervisor{
		Prepare:  server.prepareTunnel,
		Platform: linux.Platform{UserHome: userHome, Log: server.log},
		Log:      server.log,
		OnConnected: func(connected engine.Connected) {
			server.setStatus(control.Status{
				State:     control.StateConnected,
				Gateway:   connected.Gateway,
				ClientIP:  connected.ClientIP,
				Transport: connected.Transport,
			})
		},
		OnReconnecting: func(reason string) {
			server.setStatus(control.Status{State: control.StateReconnecting, Error: reason})
		},
	}
	server.stop, server.finished, server.supervisor, server.userHome = stop, finished, supervisor, userHome
	server.setStatusLocked(control.Status{State: control.StateConnecting})
	go server.run(ctx, finished, supervisor)
	return nil
}

// run keeps a tunnel up until ctx ends or retrying cannot help, and then records why it stopped.
func (server *daemon) run(ctx context.Context, finished chan struct{}, supervisor *engine.Supervisor) {
	err := supervisor.Run(ctx)
	final := control.Status{State: control.StateDisconnected}
	switch {
	case engine.NeedsLogin(err):
		final = control.Status{State: control.StateNeedsLogin, Error: err.Error()}
	case err != nil:
		final = control.Status{State: control.StateFailed, Error: err.Error()}
	}

	server.lock.Lock()
	defer server.lock.Unlock()
	server.stop, server.finished, server.supervisor = nil, nil, nil
	close(finished)
	server.setStatusLocked(final)
}

// prepareTunnel reads the settings and the saved login afresh for the next tunnel.
func (server *daemon) prepareTunnel() (engine.Login, config.Config, error) {
	profile, err := server.loadProfile()
	if err != nil {
		return engine.Login{}, config.Config{}, engine.Permanent(err)
	}
	login, err := profile.Login()
	return login, profile.Settings, err
}

// restart rebuilds a running tunnel at once, as after resume. It reports whether one was running.
func (server *daemon) restart() bool {
	server.lock.Lock()
	defer server.lock.Unlock()
	if server.supervisor == nil || !server.supervisor.Restart() {
		return false
	}
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
	profile, err := server.loadProfile()
	if err != nil {
		return err
	}
	return profile.SaveChoice(portal, gateway)
}

// prelogin returns the portal's SAML page for the client to open in a browser.
func (server *daemon) prelogin(ctx context.Context) ([]byte, time.Duration, error) {
	profile, err := server.loadProfile()
	if err != nil {
		return nil, 0, err
	}
	return profile.LoginPage(ctx)
}

// login exchanges the browser's token for a portal cookie and saves it. A tunnel that stopped
// because it needed a login starts again.
func (server *daemon) login(ctx context.Context, username, token string) error {
	profile, err := server.loadProfile()
	if err != nil {
		return err
	}
	portal, err := profile.SaveLogin(ctx, username, token)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Logged in to %s as %s.\n", portal, username)

	server.lock.Lock()
	resume := server.status.State == control.StateNeedsLogin
	userHome := server.userHome
	server.lock.Unlock()
	if resume {
		return server.connect(userHome)
	}
	return nil
}
