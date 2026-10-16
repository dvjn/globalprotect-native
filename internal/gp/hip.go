package gp

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net/url"
)

// HIPToken identifies the session in HIP requests. The gateway only checks that the
// report and the report check carry the same value. Like OpenConnect, gpn hashes the
// session fields that stay stable across logins.
func (session Session) HIPToken() string {
	stable := url.Values{
		"portal":   {session.Portal},
		"user":     {session.Username},
		"domain":   {session.Domain},
		"computer": {session.Computer},
	}
	sum := md5.Sum([]byte(stable.Encode()))
	return hex.EncodeToString(sum[:])
}

func (session Session) hipForm(clientIP string) url.Values {
	form := session.formValues()
	form.Set("client-role", "global-protect-full")
	form.Set("client-ip", clientIP)
	form.Set("md5", session.HIPToken())
	return form
}

// HIPReportNeeded asks the gateway whether it wants a HIP report for this session.
func (client *Client) HIPReportNeeded(ctx context.Context, session Session, clientIP string) (bool, error) {
	body, err := client.post(ctx, "/ssl-vpn/hipreportcheck.esp", session.hipForm(clientIP))
	if err != nil {
		return false, err
	}
	var response struct {
		Status string `xml:"status,attr"`
		Error  string `xml:"error"`
		Needed string `xml:"hip-report-needed"`
	}
	if err := xml.Unmarshal(body, &response); err != nil {
		return false, fmt.Errorf("parse HIP report check: %w", err)
	}
	if response.Status != "success" {
		return false, fmt.Errorf("HIP report check: status %q: %s", response.Status, response.Error)
	}
	return response.Needed == "yes", nil
}

// SubmitHIPReport sends the report built for this session.
func (client *Client) SubmitHIPReport(ctx context.Context, session Session, clientIP string, report []byte) error {
	form := session.hipForm(clientIP)
	form.Set("report", string(report))
	body, err := client.post(ctx, "/ssl-vpn/hipreport.esp", form)
	if err != nil {
		return err
	}
	if err := checkResponseStatus(body); err != nil {
		return fmt.Errorf("HIP report: %w", err)
	}
	return nil
}
