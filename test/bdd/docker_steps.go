/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package bdd

import (
	"github.com/cucumber/godog"
)

// DockerSteps manages Docker BDD steps
type DockerSteps struct {
	BDDContext *BDDContext
}

// NewDockerSteps returns the Docker steps
func NewDockerSteps(context *BDDContext) *DockerSteps {
	return &DockerSteps{
		BDDContext: context,
	}
}

func (d *DockerSteps) startContainer(containerID string) error {
	logger.Infof("Starting Docker container [%s]", containerID)
	_, err := d.BDDContext.Composition().issueCommand([]string{"start", containerID})
	return err
}

func (d *DockerSteps) stopContainer(containerID string) error {
	logger.Infof("Stopping Docker container [%s]", containerID)
	_, err := d.BDDContext.Composition().issueCommand([]string{"stop", containerID})
	return err
}

func (d *DockerSteps) pauseContainer(containerID string) error {
	logger.Infof("Pausing Docker container [%s]", containerID)
	_, err := d.BDDContext.Composition().issueCommand([]string{"pause", containerID})
	return err
}

func (d *DockerSteps) unpauseContainer(containerID string) error {
	logger.Infof("Un-pausing Docker container [%s]", containerID)
	_, err := d.BDDContext.Composition().issueCommand([]string{"unpause", containerID})
	return err
}

// RegisterSteps register steps
func (d *DockerSteps) RegisterSteps(s *godog.Suite) {
	s.BeforeScenario(d.BDDContext.BeforeScenario)
	s.AfterScenario(d.BDDContext.AfterScenario)

	s.Step(`^container "([^"]*)" is started$`, d.startContainer)
	s.Step(`^container "([^"]*)" is stopped$`, d.stopContainer)
	s.Step(`^container "([^"]*)" is paused$`, d.pauseContainer)
	s.Step(`^container "([^"]*)" is unpaused$`, d.unpauseContainer)
}
