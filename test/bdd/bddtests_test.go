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

	"github.com/cenkalti/backoff/v4"
	"github.com/cucumber/godog"
	"github.com/cucumber/messages-go/v10"
)

var bddContext *BDDContext

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

				testSleep := 90
				if os.Getenv("TEST_SLEEP") != "" {
					testSleep, _ = strconv.Atoi(os.Getenv("TEST_SLEEP"))
				}

				fmt.Println(fmt.Sprintf("docker-compose up with tags=%s ... waiting for orb to start for %d seconds", tags, testSleep))
				time.Sleep(time.Second * time.Duration(testSleep))
			}

			// TODO: Add this back in, but move it to a BDD test step so it doesn't run every time.
			// uploadHostMetaFileToIPNS()
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

func uploadHostMetaFileToIPNS() {
	logger.Infof("Generating key for IPNS...")

	_, err := execCMD("ipfs", "key-gen", "--ipfs-url=http://localhost:5001",
		"--key-name=OrbBDDTestKey",
		"--privatekey-ed25519=9kRTh70Ut0MKPeHY3Gdv/pi8SACx6dFjaEiIHf7JDugPpXBnCHVvRbgdzYbWfCGsXdvh/Zct+AldKG4bExjHXg")
	if err == nil {
		logger.Infof("Done generating key for IPNS.")
	} else {
		if !strings.Contains(err.Error(), "key with name 'OrbBDDTestKey' already exists") {
			panic(fmt.Sprintf("failed to execute command: %s", err.Error()))
		}
		logger.Infof("Key already generated.")
	}

	logger.Infof("Generating host-meta file...")

	attemptsCount := 0

	err = backoff.Retry(func() error {
		attemptsCount++

		_, err = execCMD("ipfs", "host-meta-doc-gen", "--ipfs-url=http://localhost:5001",
			"--resource-url=https://localhost:48326",
			"--key-name=OrbBDDTestKey", "--tls-cacerts=fixtures/keys/tls/ec-cacert.pem")
		if err != nil {
			logger.Infof("Failed to generate host-meta document (attempt %d): %s", attemptsCount, err)
			return err
		}

		return nil
	}, backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Second*3), 15))
	if err != nil {
		panic(fmt.Sprintf("failed to execute command: %s", err.Error()))
	}

	logger.Infof("Done generating host-meta file.")

	logger.Infof("Uploading host-meta file to IPNS... this may take several minutes...")

	value, err := execCMD("ipfs", "host-meta-dir-upload", "--ipfs-url=http://localhost:5001",
		"--key-name=OrbBDDTestKey", "--host-meta-input-dir=./website")
	if err != nil {
		panic(fmt.Sprintf("failed to execute command: %s", err.Error()))
	}

	logger.Infof("Done uploading host-meta file. Command output: %s", value)
}
