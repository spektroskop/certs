package main

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/spektroskop/util"
)

func formatDays(cert *x509.Certificate, bundle string) string {
	name := cert.Subject.CommonName
	days := int(cert.NotAfter.Sub(time.Now()).Hours() / 24)

	switch {
	case days < 0:
		return fmt.Sprintf(expiredFormat, name, util.Days(-days), bundle)
	case *errorDays != 0 && days < *errorDays:
		return fmt.Sprintf(errorFormat, name, util.Days(days), bundle)
	case *warnDays != 0 && days < *warnDays:
		return fmt.Sprintf(warningFormat, name, util.Days(days), bundle)
	default:
		return ""
	}
}
