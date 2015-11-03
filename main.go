package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/Sirupsen/logrus"
	"github.com/bmatcuk/doublestar"
	"github.com/spektroskop/util"
)

var (
	caGlob    = flag.String("ca", "", "")
	errorDays = flag.Int("err", 0, "")
	warnDays  = flag.Int("warn", 0, "")
	verify    = flag.Bool("verify", false, "")

	expiredFormat = "ERROR: %s expired %s ago (%s)"
	warningFormat = "WARNING: %s will expire in %s (%s)"
	errorFormat   = "ERROR: %s will expire in %s (%s)"
	verifyFormat  = "ERROR: %s: %s: %s (%s)"
)

type Unit struct {
	data []byte
	name string
}

func main() {
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, `usage: check-certs ([-err DAYS] [-warn DAYS] | -verify [-ca "GLOB"]) "<GLOBS...>"

  -err    DAYS  Number of days before expiry to generate an ERROR message
  -warn   DAYS  Number of days before expiry to generate an WARNING message
  -verify       Verify certificate chain
  -ca     GLOB  Trusted root certificates
		`)
		os.Exit(2)
	}

	flag.Parse()

	if flag.NArg() < 1 {
		util.Usage()
	}

	var bundles []string
	for _, arg := range flag.Args() {
		if b, err := doublestar.Glob(arg); err != nil {
			logrus.Fatal(err)
		} else {
			bundles = append(bundles, b...)
		}
	}

	var files = util.Files(bundles)
	if len(files) == 0 {
		os.Exit(1)
	}

	var proc Processor = DayProcessor{}

	if *verify {
		proc = ChainProcessor{x509.NewCertPool()}

		if *caGlob != "" {
			cas, err := doublestar.Glob(*caGlob)
			if err != nil {
				logrus.Fatal(err)
			}
			for _, bundle := range util.Files(cas) {
				if data, err := ioutil.ReadFile(bundle); err != nil {
					logrus.Fatal(err)
				} else {
					proc.(ChainProcessor).Roots.AppendCertsFromPEM(data)
				}
			}
		}
	}

	Run(files, proc)
}

func Run(files []string, proc Processor) {
	messages := make(chan string)
	incoming := make(chan Unit, len(files))
	var group sync.WaitGroup

	go func() {
		for _, bundle := range files {
			if data, err := ioutil.ReadFile(bundle); err == nil {
				incoming <- Unit{data, bundle}
			}
		}
		close(incoming)
	}()

	group.Add(1)
	go func() {
		for unit := range incoming {
			group.Add(1)
			go proc.Process(&group, messages, unit)
		}
		group.Done()
	}()

	go func() {
		group.Wait()
		close(messages)
	}()

	for message := range messages {
		if message != "" {
			fmt.Println(message)
		}
	}
}
