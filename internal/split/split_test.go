package split

import (
	"bytes"
	"errors"
	"net"
	"slices"
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

func TestRoutingDomains(t *testing.T) {
	got := NewDomains([]string{"*.corp.example", "wiki.example.org:443", "corp.example"}).RoutingDomains()
	if want := []string{"~corp.example", "~wiki.example.org"}; !slices.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
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

func TestMatchedAddressesFollowsCNAMEs(t *testing.T) {
	domains := NewDomains([]string{"*.linkedin.com"})
	cname := dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("www.linkedin.com."), Type: dnsmessage.TypeCNAME, Class: dnsmessage.ClassINET, TTL: 300},
		Body:   &dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("cdn.example.net.")},
	}
	message := answer(t, "www.linkedin.com.", cname,
		aRecord("cdn.example.net.", 60, [4]byte{192, 0, 2, 1}),
		aRecord("cdn.example.net.", 120, [4]byte{192, 0, 2, 2}))

	addresses, ttl, matched, err := matchedAddresses(message, domains)
	if err != nil {
		t.Fatal(err)
	}
	if !matched || ttl != 60*time.Second || len(addresses) != 2 || !addresses[1].Equal(net.IPv4(192, 0, 2, 2)) {
		t.Errorf("got %v, %s, %t", addresses, ttl, matched)
	}
}

func TestMatchedAddressesIgnoresOtherNames(t *testing.T) {
	message := answer(t, "example.com.", aRecord("example.com.", 60, [4]byte{192, 0, 2, 9}))
	addresses, _, matched, err := matchedAddresses(message, NewDomains([]string{"*.linkedin.com"}))
	if err != nil || matched || addresses != nil {
		t.Errorf("got %v, %t, %v", addresses, matched, err)
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

func TestWithoutIPv6(t *testing.T) {
	domains := NewDomains([]string{"*.corp.example"})
	query := func(name string, kind dnsmessage.Type) []byte {
		builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7, RecursionDesired: true})
		builder.StartQuestions()
		builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET})
		message, err := builder.Finish()
		if err != nil {
			t.Fatal(err)
		}
		return message
	}

	answer, blocked := withoutIPv6(query("wiki.corp.example.", dnsmessage.TypeAAAA), domains)
	if !blocked {
		t.Fatal("an AAAA query for a matching name is not answered")
	}
	var parser dnsmessage.Parser
	header, err := parser.Start(answer)
	if err != nil || header.ID != 7 || !header.Response || header.RCode != dnsmessage.RCodeSuccess {
		t.Errorf("got header %+v, %v", header, err)
	}
	parser.SkipAllQuestions()
	if _, err := parser.AnswerHeader(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		t.Errorf("the answer has records: %v", err)
	}

	if _, blocked := withoutIPv6(query("wiki.corp.example.", dnsmessage.TypeA), domains); blocked {
		t.Error("an A query is answered")
	}
	if _, blocked := withoutIPv6(query("example.com.", dnsmessage.TypeAAAA), domains); blocked {
		t.Error("an AAAA query for another name is answered")
	}
}
