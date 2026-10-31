package hip

// Profile is everything a client says about the machine, as opposed to the session: in the
// HIP report, and, for the host ID, serial number, computer, OS and client version, in the
// login. A client exports it, and can import another's to report instead of what it detects.
// Any client reads any other's, so a phone can log in and report as the laptop it was
// exported from.
//
// In an imported profile, empty strings and null lists leave what the client detects; an
// empty list reports none.
type Profile struct {
	OS            string      `json:"os,omitempty"`
	OSVendor      string      `json:"os_vendor,omitempty"`
	Computer      string      `json:"computer,omitempty"`
	HostID        string      `json:"host_id,omitempty"`
	SerialNumber  string      `json:"serial_number,omitempty"`
	HostDomain    string      `json:"host_domain,omitempty"`
	ClientVersion string      `json:"client_version,omitempty"`
	Products      []Product   `json:"products"`
	Drives        []Drive     `json:"drives"`
	Interfaces    []Interface `json:"interfaces"`
}

// Over is base with every field profile sets replacing base's.
func (profile Profile) Over(base Profile) Profile {
	pick := func(override, original string) string {
		if override != "" {
			return override
		}
		return original
	}
	merged := Profile{
		OS:            pick(profile.OS, base.OS),
		OSVendor:      pick(profile.OSVendor, base.OSVendor),
		Computer:      pick(profile.Computer, base.Computer),
		HostID:        pick(profile.HostID, base.HostID),
		SerialNumber:  pick(profile.SerialNumber, base.SerialNumber),
		HostDomain:    pick(profile.HostDomain, base.HostDomain),
		ClientVersion: pick(profile.ClientVersion, base.ClientVersion),
		Products:      base.Products,
		Drives:        base.Drives,
		Interfaces:    base.Interfaces,
	}
	if profile.Products != nil {
		merged.Products = profile.Products
	}
	if profile.Drives != nil {
		merged.Drives = profile.Drives
	}
	if profile.Interfaces != nil {
		merged.Interfaces = profile.Interfaces
	}
	return merged
}
