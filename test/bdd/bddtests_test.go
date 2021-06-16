/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/cucumber/messages-go/v10"
	jsonldcontext "github.com/hyperledger/aries-framework-go/pkg/client/jsonld/context"

	"github.com/trustbloc/orb/internal/pkg/ldcontext"
)

var bddContext *BDDContext

// services that will be populated with the contexts.
var services = []string{
	"http://localhost:8077",   // vct
	"https://localhost:48326", // orb domain-1
	"https://localhost:48426", // orb domain-2
	"https://localhost:48626", // orb domain-2
}

func TestMain(m *testing.M) {
	// default is to run all tests with tag @all
	tags := "all"

	if os.Getenv("TAGS") != "" {
		tags = os.Getenv("TAGS")
	}

	flag.Parse()

	cmdTags := flag.CommandLine.Lookup("test.run")
	if cmdTags != nil && cmdTags.Value != nil && cmdTags.Value.String() != "" {
		tags = cmdTags.Value.String()
	}

	compose := os.Getenv("DISABLE_COMPOSITION") != "true"

	state := newState()

	status := godog.RunWithOptions("godogs", func(s *godog.Suite) {
		s.BeforeSuite(func() {
			if compose {
				if err := bddContext.Composition().Up(); err != nil {
					panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
				}

				testSleep := 80
				if os.Getenv("TEST_SLEEP") != "" {
					testSleep, _ = strconv.Atoi(os.Getenv("TEST_SLEEP"))
				}

				fmt.Println(fmt.Sprintf("docker-compose up with tags=%s ... waiting for orb to start for %d seconds", tags, testSleep))
				time.Sleep(time.Second * time.Duration(testSleep))
			}

			for _, service := range services {
				if err := AddJSONLDContexts(service); err != nil {
					panic(err)
				}
			}
		})

		s.AfterSuite(func() {
			if compose {
				composition := bddContext.Composition()
				if err := composition.GenerateLogs(); err != nil {
					logger.Warnf("Error generating logs: %s", err)
				}
				if _, err := composition.Decompose(); err != nil {
					logger.Warnf("Error decomposing: %s", err)
				}
			}
		})

		s.BeforeScenario(func(pickle *messages.Pickle) {
			state.clear()

			logger.Infof("\n\n********** Running scenario: %s **********", pickle.GetName())
		})

		FeatureContext(s, state)
	}, godog.Options{
		Tags:          tags,
		Format:        "progress",
		Paths:         []string{"features"},
		Randomize:     time.Now().UTC().UnixNano(), // randomize scenario execution order
		Strict:        true,
		StopOnFailure: true,
	})

	if st := m.Run(); st > status {
		status = st
	}
	os.Exit(status)
}

func FeatureContext(s *godog.Suite, state *state) {
	var err error
	bddContext, err = NewBDDContext()
	if err != nil {
		panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
	}

	// Need a unique name, but docker does not allow '-' in names
	composeProjectName := strings.Replace(generateUUID(), "-", "", -1)
	composition, err := NewComposition(composeProjectName, "docker-compose.yml", "./fixtures")
	if err != nil {
		panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
	}

	bddContext.SetComposition(composition)

	// Context is shared between tests - for now
	NewCommonSteps(bddContext, state).RegisterSteps(s)
	NewDockerSteps(bddContext).RegisterSteps(s)
	NewDIDSideSteps(bddContext, state, "did:orb").RegisterSteps(s)
	NewCLISteps(bddContext, state).RegisterSteps(s)
	NewDriverSteps(bddContext, state).RegisterSteps(s)
}

// AddJSONLDContexts imports extra contexts for the service instance.
func AddJSONLDContexts(serviceURL string) error {
	return jsonldcontext.NewClient(serviceURL, jsonldcontext.WithHTTPClient(&http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint: gosec
		},
	})).Add(context.Background(), ldcontext.MustGetExtra()...)
}
