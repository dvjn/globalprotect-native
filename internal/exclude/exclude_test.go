package exclude

import (
	"bytes"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDomains(t *testing.T) {
	domains := NewDomains([]string{"*.linkedin.com", "fast.com", "www.irctc.co.in:443", " Download.Microsoft.com "})
	tests := map[string]bool{
		"www.linkedin.com":         true,
		"media.licdn.linkedin.com": true,
		"linkedin.com":             false,
		"notlinkedin.com":          false,
		"fast.com":                 true,
		"fast.com.":                true,
		"api.fast.com":             false,
		"www.irctc.co.in":          true,
		"download.microsoft.com":   true,
		"example.com":              false,
	}
	for name, want := range tests {
		if got := domains.Match(name); got != want {
			t.Errorf("Match(%q) = %t, want %t", name, got, want)
		}
	}
	if !NewDomains(nil).Empty() || domains.Empty() || domains.Count() != 4 {
		t.Errorf("Empty() or Count() is wrong: Count() = %d", domains.Count())
	}
	if NewDomains([]string{"fast.com", "FAST.com"}).Count() != 1 {
		t.Error("a repeated entry is counted twice")
	}
}

func answer(t *testing.T, question string, records ...dnsmessage.Resource) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
	builder.StartQuestions()
	builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(question), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	builder.StartAnswers()
	for _, record := range records {
		switch body := record.Body.(type) {
		case *dnsmessage.AResource:
			builder.AResource(record.Header, *body)
		case *dnsmessage.CNAMEResource:
			builder.CNAMEResource(record.Header, *body)
		}
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func aRecord(name string, ttl uint32, address [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName(name), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: ttl},
		Body:   &dnsmessage.AResource{A: address},
	}
}

func TestExcludedAddressesFollowsCNAMEs(t *testing.T) {
	domains := NewDomains([]string{"*.linkedin.com"})
	cname := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("www.linkedin.com."), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.net.")},
	}
	message := answer(t, "www.linkedin.com.", cname,
		aRecord("cdn.example.net.", 60, [4]byte{192, 0, 2, 1}),
		aRecord("cdn.example.net.", 120, [4]byte{192, 0, 2, 2}))

	addresses, ttl, excluded, err := excludedAddresses(message, domains)
	if err != nil {
		t.Fatal(err)
	}
	if !excluded || ttl != 60*time.Second || len(addresses) != 2 || !addresses[1].Equal(net.IPv4(192, 0, 2, 2)) {
		t.Errorf("got %v, %s, %t", addresses, ttl, excluded)
	}
}

func TestExcludedAddressesIgnoresOtherNames(t *testing.T) {
	message := answer(t, "example.com.", aRecord("example.com.", 60, [4]byte{192, 0, 2, 9}))
	addresses, _, excluded, err := excludedAddresses(message, NewDomains([]string{"*.linkedin.com"}))
	if err != nil || excluded || addresses != nil {
		t.Errorf("got %v, %t, %v", addresses, excluded, err)
	}
}

func TestTCPMessageFraming(t *testing.T) {
	var stream bytes.Buffer
	if err := writeTCPMessage(&stream, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := stream.Bytes()[:2]; got[0] != 0 || got[1] != 5 {
		t.Errorf("length prefix = %v, want [0 5]", got)
	}
	message, err := readTCPMessage(&stream)
	if err != nil || string(message) != "hello" {
		t.Errorf("got %q, %v", message, err)
	}
}
