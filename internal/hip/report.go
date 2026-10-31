package hip

import (
	"encoding/xml"
	"net/url"
	"time"
)

// Input is everything a HIP report states.
type Input struct {
	MD5           string
	Username      string
	Domain        string
	HostDomain    string
	Computer      string
	HostID        string
	ClientIP      string
	ClientVersion string
	OS            string
	OSVendor      string
	Products      []Product
	Facts         Facts
	Now           time.Time
}

// The categories in the order the official client reports them.
var categories = []string{
	"anti-malware",
	"disk-backup",
	"disk-encryption",
	"firewall",
	"patch-management",
	"data-loss-prevention",
}

type report struct {
	XMLName      xml.Name   `xml:"hip-report"`
	MD5          string     `xml:"md5-sum"`
	UserName     string     `xml:"user-name"`
	Domain       string     `xml:"domain"`
	HostName     string     `xml:"host-name"`
	HostID       string     `xml:"host-id"`
	IPAddress    string     `xml:"ip-address"`
	IPv6Address  string     `xml:"ipv6-address"`
	GenerateTime string     `xml:"generate-time"`
	Version      int        `xml:"hip-report-version"`
	Categories   []category `xml:"categories>entry"`
}

type category struct {
	Name string `xml:"name,attr"`
	*hostInfo
	List           *productList `xml:"list"`
	MissingPatches *struct{}    `xml:"missing-patches"`
}

type hostInfo struct {
	ClientVersion     string             `xml:"client-version"`
	OS                string             `xml:"os"`
	OSVendor          string             `xml:"os-vendor"`
	Domain            string             `xml:"domain"`
	HostName          string             `xml:"host-name"`
	HostID            string             `xml:"host-id"`
	NetworkInterfaces []networkInterface `xml:"network-interface>entry"`
}

type networkInterface struct {
	Name        string        `xml:"name,attr"`
	Description string        `xml:"description"`
	MAC         string        `xml:"mac-address"`
	IPv4        []nameElement `xml:"ip-address>entry"`
	IPv6        []nameElement `xml:"ipv6-address>entry"`
}

type nameElement struct {
	Name string `xml:"name,attr"`
}

type productList struct {
	Entries []productEntry `xml:"entry"`
}

type productEntry struct {
	Info productInfo `xml:"ProductInfo"`
}

type productInfo struct {
	Prod               prod    `xml:"Prod"`
	RealTimeProtection string  `xml:"real-time-protection,omitempty"`
	LastFullScanTime   string  `xml:"last-full-scan-time,omitempty"`
	IsEnabled          string  `xml:"is-enabled,omitempty"`
	LastBackupTime     string  `xml:"last-backup-time,omitempty"`
	Drives             []drive `xml:"drives>entry"`
}

type prod struct {
	Vendor      string `xml:"vendor,attr"`
	Name        string `xml:"name,attr"`
	Version     string `xml:"version,attr"`
	ProductType string `xml:"prodType,attr,omitempty"`
	OSType      string `xml:"osType,attr,omitempty"`
}

type drive struct {
	Name  string `xml:"drive-name"`
	State string `xml:"enc-state"`
}

// Build renders the HIP report XML.
func Build(input Input) ([]byte, error) {
	document := report{
		MD5:          input.MD5,
		UserName:     url.QueryEscape(input.Username),
		Domain:       input.Domain,
		HostName:     input.Computer,
		HostID:       input.HostID,
		IPAddress:    input.ClientIP,
		GenerateTime: input.Now.Format("01/02/2006 15:04:05"),
		Version:      4,
		Categories:   []category{hostInfoCategory(input)},
	}
	for _, name := range categories {
		document.Categories = append(document.Categories, buildCategory(name, input.Products, input.Facts))
	}

	body, err := xml.MarshalIndent(document, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(xml.Header), body...), nil
}

func hostInfoCategory(input Input) category {
	info := &hostInfo{
		ClientVersion: input.ClientVersion,
		OS:            input.OS,
		OSVendor:      input.OSVendor,
		Domain:        input.HostDomain,
		HostName:      input.Computer,
		HostID:        input.HostID,
	}
	for _, found := range input.Facts.Interfaces {
		entry := networkInterface{Name: found.Name, Description: found.Name, MAC: found.MAC}
		for _, address := range found.IPv4 {
			entry.IPv4 = append(entry.IPv4, nameElement{address})
		}
		for _, address := range found.IPv6 {
			entry.IPv6 = append(entry.IPv6, nameElement{address})
		}
		info.NetworkInterfaces = append(info.NetworkInterfaces, entry)
	}
	return category{Name: "host-info", hostInfo: info}
}

func buildCategory(name string, products []Product, facts Facts) category {
	built := category{Name: name, List: &productList{}}
	if name == "patch-management" {
		built.MissingPatches = &struct{}{}
	}

	for _, product := range products {
		if product.Category != name {
			continue
		}
		info := productInfo{Prod: prod{Vendor: product.Vendor, Name: product.Name, Version: product.Version}}
		switch name {
		case "anti-malware":
			// The official Linux client marks anti-malware products as type 3 on OS type 1.
			info.Prod.ProductType, info.Prod.OSType = "3", "1"
			info.RealTimeProtection = product.State
			info.LastFullScanTime = "n/a"
		case "disk-backup":
			info.LastBackupTime = "n/a"
		case "disk-encryption":
			info.Drives = drivesWithTotal(facts.Drives)
		default:
			info.IsEnabled = product.State
		}
		built.List.Entries = append(built.List.Entries, productEntry{Info: info})
	}
	return built
}

// drivesWithTotal adds the "All" entry the official client reports after the individual drives.
func drivesWithTotal(found []Drive) []drive {
	allEncrypted := len(found) > 0
	var drives []drive
	for _, each := range found {
		drives = append(drives, drive{Name: each.Name, State: encryptionState(each.Encrypted)})
		allEncrypted = allEncrypted && each.Encrypted
	}
	return append(drives, drive{Name: "All", State: encryptionState(allEncrypted)})
}

func yesNo(value bool) string {
	if value {
		return "yes"
	}
	return "no"
}

func encryptionState(encrypted bool) string {
	if encrypted {
		return "encrypted"
	}
	return "unencrypted"
}
