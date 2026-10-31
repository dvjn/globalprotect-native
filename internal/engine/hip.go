package engine

import (
	"context"
	"strings"
	"time"

	"github.com/dvjn/globalprotect-native/internal/gp"
	"github.com/dvjn/globalprotect-native/internal/hip"
)

// HIPProfile is what the HIP report says about the machine: the platform's detected profile
// over what identity and username give, with override over both. Exporting it, or importing
// it as another client's override, reports the same machine.
func HIPProfile(identity gp.Identity, username string, platform Platform, override hip.Profile) hip.Profile {
	base := identityProfile(identity)
	base.OSVendor = "Linux"
	_, base.HostDomain, _ = strings.Cut(username, "@")
	return override.Over(platform.HIPProfile().Over(base))
}

// identityProfile is what identity says about the machine.
func identityProfile(identity gp.Identity) hip.Profile {
	return hip.Profile{
		HostID:        identity.HostID,
		SerialNumber:  identity.SerialNumber,
		Computer:      identity.Computer,
		OS:            identity.OSVersion,
		ClientVersion: identity.ClientVersion,
	}
}

// BuildHIPReport describes the machine to the gateway for the session.
func BuildHIPReport(opened Session, clientIP string, platform Platform) ([]byte, error) {
	sessionDomain := opened.Session.Domain
	if sessionDomain == "(empty_domain)" {
		sessionDomain = ""
	}
	profile := HIPProfile(opened.Client.Identity, opened.Session.Username, platform, opened.HIP)
	return hip.Build(hipInput(profile, opened.Session.HIPToken(), opened.Session.Username, sessionDomain, clientIP))
}

// PreviewHIPReport is the report profile gives, with placeholders for what each session sets.
func PreviewHIPReport(profile hip.Profile, username string) ([]byte, error) {
	return hip.Build(hipInput(profile, "(set by each session)", username, "", "(assigned by the gateway)"))
}

func hipInput(profile hip.Profile, md5, username, domain, clientIP string) hip.Input {
	return hip.Input{
		MD5:           md5,
		Username:      username,
		Domain:        domain,
		HostDomain:    profile.HostDomain,
		Computer:      profile.Computer,
		HostID:        profile.HostID,
		ClientIP:      clientIP,
		ClientVersion: profile.ClientVersion,
		OS:            profile.OS,
		OSVendor:      profile.OSVendor,
		Products:      profile.Products,
		Facts:         hip.Facts{Drives: profile.Drives, Interfaces: profile.Interfaces},
		Now:           time.Now(),
	}
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
