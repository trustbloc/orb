/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cucumber/godog"
	"github.com/cucumber/messages-go/v10"
)

var context *BDDContext

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
				if err := context.Composition().Up(); err != nil {
					panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
				}

				testSleep := 30
				if os.Getenv("TEST_SLEEP") != "" {
					testSleep, _ = strconv.Atoi(os.Getenv("TEST_SLEEP"))
				}

				fmt.Println(fmt.Sprintf("docker-compose up with tags=%s ... waiting for orb to start for %d seconds", tags, testSleep))
				time.Sleep(time.Second * time.Duration(testSleep))
			}
		})

		s.AfterSuite(func() {
			if compose {
				composition := context.Composition()
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
	context, err = NewBDDContext()
	if err != nil {
		panic(fmt.Sprintf("Error returned from NewBDDContext: %s", err))
	}

	// Need a unique name, but docker does not allow '-' in names
	composeProjectName := strings.Replace(generateUUID(), "-", "", -1)
	composition, err := NewComposition(composeProjectName, "docker-compose.yml", "./fixtures")
	if err != nil {
		panic(fmt.Sprintf("Error composing system in BDD context: %s", err))
	}

	context.SetComposition(composition)

	// Context is shared between tests - for now
	NewCommonSteps(context, state).RegisterSteps(s)
	NewDockerSteps(context).RegisterSteps(s)
	NewDIDSideSteps(context, state, "did:orb").RegisterSteps(s)
	NewCLISteps(context, state).RegisterSteps(s)
	NewDriverSteps(context, state).RegisterSteps(s)
}
