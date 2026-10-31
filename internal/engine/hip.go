package engine

import (
	"context"
	"strings"
	"time"

	"github.com/dvjn/globalprotect-native/internal/hip"
)

// BuildHIPReport describes the machine to the gateway, with the platform's inventory.
func BuildHIPReport(opened Session, clientIP string, platform Platform) ([]byte, error) {
	sessionDomain := opened.Session.Domain
	if sessionDomain == "(empty_domain)" {
		sessionDomain = ""
	}
	_, emailDomain, _ := strings.Cut(opened.Session.Username, "@")
	products, facts := platform.HIPInventory()
	identity := opened.Client.Identity
	return hip.Build(hip.Input{
		MD5:           opened.Session.HIPToken(),
		Username:      opened.Session.Username,
		Domain:        sessionDomain,
		HostDomain:    emailDomain,
		Computer:      opened.Session.Computer,
		HostID:        identity.HostID,
		ClientIP:      clientIP,
		ClientVersion: identity.ClientVersion,
		OS:            identity.OSVersion,
		Products:      products,
		Facts:         facts,
		Now:           time.Now(),
	})
}

// sendHIPReportIfNeeded submits a report when the gateway asks for one.
func sendHIPReportIfNeeded(ctx context.Context, opened Session, clientIP string, platform Platform) error {
	needed, err := opened.Client.HIPReportNeeded(ctx, opened.Session, clientIP)
	if err != nil || !needed {
		return err
	}
	report, err := BuildHIPReport(opened, clientIP, platform)
	if err != nil {
		return err
	}
	if err := opened.Client.SubmitHIPReport(ctx, opened.Session, clientIP, report); err != nil {
		return err
	}
	opened.log.Println("Sent the HIP report.")
	return nil
}

// resendHIPReports sends a report whenever the gateway wants one, every interval, until ctx ends.
func resendHIPReports(ctx context.Context, opened Session, clientIP string, platform Platform, interval time.Duration) {
	if interval <= 0 {
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := sendHIPReportIfNeeded(ctx, opened, clientIP, platform); err != nil {
				opened.log.Println("HIP report:", err)
			}
		}
	}
}
