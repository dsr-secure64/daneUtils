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

func printSMIMEArecord(userName string, userDomain string, certPEMfile string, usage int,
	selector int, matchType int) error {
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

	common_name := userName + "@" + userDomain
	if cert.Subject.CommonName != common_name {
		return fmt.Errorf("Common Name mismatch\n")
	}

	smimea := new(dns.SMIMEA)
	smime_dname, error := dns.SMIMEAName(userName, userDomain)
	if error != nil {
		return error
	} else {
		fmt.Fprintf(os.Stdout, "SMIMEA name: %s\n", smime_dname)
	}

	smimea.Hdr.Name = smime_dname
	smimea.Hdr = dns.RR_Header{Name: smimea.Hdr.Name, Rrtype: dns.TypeSMIMEA,
		Class: dns.ClassINET, Ttl: 3600}

	err := smimea.Sign(usage, selector, matchType, cert)

	if err != nil {
		return err
	} else {
		fmt.Fprintf(os.Stdout, "SMIMEA record: %s\n", smimea.String())
	}

	return nil
}


func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	
	userNamePtr := flag.String("username", "", "email user name")
	userDomainPtr := flag.String("userdomain", "", "email user domain association")
	certFilePtr := flag.String("certPEMFile", "", "certificate file in PEM format")

	usagePtr := flag.Int("usage", 0, "DANE certificate usage field")
	selectorPtr := flag.Int("selector", 0, "DANE certificate selector field")
	matchTypePtr := flag.Int("matchType", 0, "Dane matching type field")

	flag.Parse()

	if len(os.Args) < 6 {
		flag.Usage()
		os.Exit(1)
	}	

	err := printSMIMEArecord(*userNamePtr, *userDomainPtr, *certFilePtr, *usagePtr,
		*selectorPtr, *matchTypePtr)
	if err != nil {
		fmt.Fprintf(os.Stdout, "failed to create certificate: %v\n", err)
	}
}
