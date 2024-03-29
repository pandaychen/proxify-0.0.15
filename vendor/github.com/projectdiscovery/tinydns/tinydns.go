package tinydns

import (
	"bytes"
	"encoding/gob"
	"fmt"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/hmap/store/hybrid"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

type TinyDNS struct {
	options    *Options
	server     *dns.Server
	hm         *hybrid.HybridMap
	OnServeDns func(data Info)
}

type Info struct {
	Domain    string
	Operation string
	Wildcard  bool
	Msg       string
	Upstream  string
}

func New(options *Options) (*TinyDNS, error) {
	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}

	tinydns := &TinyDNS{
		options: options,
		hm:      hm,
	}

	srv := &dns.Server{
		Addr:    options.ListenAddress,
		Net:     options.Net,
		Handler: tinydns,
	}
	tinydns.server = srv

	return tinydns, nil
}

func (t *TinyDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	var info Info
	domain := r.Question[0].Name
	domainlookup := strings.TrimSuffix(domain, ".")
	info.Domain = domainlookup
	info.Operation = "request"
	info.Msg = fmt.Sprintf("Received request for: %s\n", domainlookup)
	if t.OnServeDns != nil {
		t.OnServeDns(info)
	}
	switch r.Question[0].Qtype {
	case dns.TypeA:
		// attempts in order to retrieve the record in the following fallback-chain
		if dnsRecord, ok := t.options.DnsRecords[domainlookup]; ok { // - hardcoded records
			info.Domain = domainlookup
			info.Operation = "in-memory"
			info.Wildcard = false
			info.Msg = fmt.Sprintf("Using in-memory record for %s.\n", domainlookup)
			if t.OnServeDns != nil {
				t.OnServeDns(info)
			}
			_ = w.WriteMsg(reply(r, domain, dnsRecord))

		} else if dnsRecord, ok = t.options.DnsRecords["*"]; ok { // - wildcard
			info.Domain = domainlookup
			info.Operation = "in-memory"
			info.Wildcard = true
			info.Msg = fmt.Sprintf("Using in-memory wildcard record for %s.\n", domainlookup)
			if t.OnServeDns != nil {
				t.OnServeDns(info)
			}
			_ = w.WriteMsg(reply(r, domain, dnsRecord))
		} else if dnsRecordBytes, ok := t.hm.Get(domain); ok { // - cache
			dnsRecord := &DnsRecord{}
			err := gob.NewDecoder(bytes.NewReader(dnsRecordBytes)).Decode(dnsRecord)
			if err == nil {
				info.Domain = domainlookup
				info.Operation = "cached"
				info.Wildcard = false
				info.Msg = fmt.Sprintf("Using cached record for %s.\n", domainlookup)
				if t.OnServeDns != nil {
					t.OnServeDns(info)
				}
				_ = w.WriteMsg(reply(r, domain, dnsRecord))
			}
		} else if len(t.options.UpstreamServers) > 0 {
			// upstream and store in cache
			upstreamServer := sliceutil.PickRandom(t.options.UpstreamServers)
			info.Domain = domainlookup
			info.Operation = "cached"
			info.Wildcard = false
			info.Upstream = upstreamServer
			info.Msg = fmt.Sprintf("Retrieving records for %s with upstream %s.\n", domainlookup, upstreamServer)
			if t.OnServeDns != nil {
				t.OnServeDns(info)
			}
			msg, err := dns.Exchange(r, upstreamServer)
			if err == nil {
				_ = w.WriteMsg(msg)
				dnsRecord := &DnsRecord{}
				for _, record := range msg.Answer {
					switch recordType := record.(type) {
					case *dns.A:
						dnsRecord.A = append(dnsRecord.A, recordType.A.String())
					case *dns.AAAA:
						dnsRecord.AAAA = append(dnsRecord.AAAA, recordType.AAAA.String())
					}
				}
				var dnsRecordBytes bytes.Buffer
				if err := gob.NewEncoder(&dnsRecordBytes).Encode(dnsRecord); err == nil {
					info.Domain = domainlookup
					info.Operation = "saving"
					info.Wildcard = false
					info.Upstream = upstreamServer
					info.Msg = fmt.Sprintf("Saving records for %s in cache.\n", domainlookup)
					if t.OnServeDns != nil {
						t.OnServeDns(info)
					}
					_ = t.hm.Set(domain, dnsRecordBytes.Bytes())
				}
			}
		}
	}
	_ = w.WriteMsg(reply(r, domain, &DnsRecord{}))
}

func reply(r *dns.Msg, domain string, dnsRecord *DnsRecord) *dns.Msg {
	msg := dns.Msg{}
	msg.SetReply(r)
	msg.Authoritative = true
	for _, a := range dnsRecord.A {
		msg.Answer = append(msg.Answer, &dns.A{
			Hdr: dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP(a),
		})
	}
	for _, aaaa := range dnsRecord.AAAA {
		msg.Answer = append(msg.Answer, &dns.AAAA{
			Hdr:  dns.RR_Header{Name: domain, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP(aaaa),
		})
	}
	return &msg
}

func (t *TinyDNS) Run() error {
	return t.server.ListenAndServe()
}

func (t *TinyDNS) Close() {
	t.hm.Close()
}
