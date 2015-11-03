package main

import (
	"crypto/x509"
	"fmt"
	"strings"
	"sync"

	"github.com/spektroskop/certutil"
)

type Processor interface {
	Process(*sync.WaitGroup, chan string, Unit)
}

type DayProcessor struct{}

func (p DayProcessor) Process(group *sync.WaitGroup, m chan string, unit Unit) {
	certs, _ := certutil.SplitBundle(unit.data)

	for _, cert := range certs {
		m <- formatDays(cert, unit.name)
	}

	group.Done()
}

type ChainProcessor struct {
	Roots *x509.CertPool
}

func (p ChainProcessor) Process(group *sync.WaitGroup, m chan string, unit Unit) {
	certs, issuers := certutil.SplitBundle(unit.data)
	options := x509.VerifyOptions{Intermediates: issuers.Pool(), Roots: p.Roots}

	for _, cert := range certs.Verify(options) {
		if cert.Error != nil {
			switch {
			case strings.Contains(cert.Error.Error(), "unknown authority"):
				m <- fmt.Sprintf(verifyFormat, cert.Subject.CommonName, cert.Error, cert.Issuer.CommonName, unit.name)
			case strings.Contains(cert.Error.Error(), "expired"):
				m <- fmt.Sprintf(verifyFormat, cert.Subject.CommonName, cert.Error, cert.NotAfter.Format("2006-01-02"), unit.name)
			}
		} else {
			m <- formatDays(cert.Certificate, unit.name)
		}
	}

	group.Done()
}
