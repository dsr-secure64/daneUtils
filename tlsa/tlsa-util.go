package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"io/ioutil"
	"os"
)

func printTLSArecord(fqdnName string, certPEMfile string, usage int,
	selector int, matchType int, network string, service string) error {
	input_certificate, read_err := ioutil.ReadFile(certPEMfile)
	if read_err != nil {
		return read_err
	}
	block, _ := pem.Decode(input_certificate)

	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	if cert == nil {
		return fmt.Errorf("Error creating certificate\n")
	}

	common_name := fqdnName
	if cert.Subject.CommonName != common_name {
		return fmt.Errorf("Common Name mismatch\n")
	}

	tlsa := new(dns.TLSA)
	tlsa_dname, error := dns.TLSAName(fqdnName + ".", service, network)
	if error != nil {
		return error
	} else {
		fmt.Fprintf(os.Stdout, "TLSA name: %s\n", tlsa_dname)
	}

	tlsa.Hdr.Name = tlsa_dname
	tlsa.Hdr = dns.RR_Header{Name: tlsa.Hdr.Name, Rrtype: dns.TypeTLSA,
		Class: dns.ClassINET, Ttl: 3600}

	err := tlsa.Sign(usage, selector, matchType, cert)

	if err != nil {
		return err
	} else {
		fmt.Fprintf(os.Stdout, "TLSA record: %s\n", tlsa.String())
	}

	return nil
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}

	fqdnPtr := flag.String("fqdn", "", "fully qualified domain name")
	certFilePtr := flag.String("certPEMFile", "", "TLS certificate file iQn PEM format")
	servicePtr := flag.String("service", "", "/etc/services defined application")
	networkPtr := flag.String("network", "", "network protocol: tcp, udp")

	usagePtr := flag.Int("usage", 0, "DANE certificate usage field")
	selectorPtr := flag.Int("selector", 0, "DANE certificate selector field")
	matchTypePtr := flag.Int("matchType", 0, "Dane matching type field")

	flag.Parse()

	if len(os.Args) < 7 {
		flag.Usage()
		os.Exit(1)
	}

	err := printTLSArecord(*fqdnPtr, *certFilePtr, *usagePtr, *selectorPtr,
		*matchTypePtr, *networkPtr, *servicePtr)
	if err != nil {
		fmt.Fprintf(os.Stdout, "failed to create certificate: %v\n", err)
	}
}
