/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0

*/

package bdd

import (
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"

	docker "github.com/fsouza/go-dockerclient"
)

const dockerComposeCommand = "docker-compose"

// Composition represents a docker-compose execution and management
type Composition struct {
	dockerClient  *docker.Client
	apiContainers []docker.APIContainers

	composeFilesYaml string
	projectName      string
	dockerHelper     DockerHelper

	dir string
}

// NewComposition create a new Composition specifying the project name (for isolation) and the compose files.
func NewComposition(projectName string, composeFilesYaml string, dir string) (composition *Composition, err error) {
	errRetFunc := func() error {
		return fmt.Errorf("Error creating new composition '%s' using compose yaml '%s':  %s", projectName, composeFilesYaml, err)
	}

	endpoint := "unix:///var/run/docker.sock"
	composition = &Composition{composeFilesYaml: composeFilesYaml, projectName: projectName, dir: dir}
	if composition.dockerClient, err = docker.NewClient(endpoint); err != nil {
		return nil, errRetFunc()
	}
	if _, err = composition.issueCommand([]string{"up", "--force-recreate", "-d"}); err != nil {
		return nil, errRetFunc()
	}
	if composition.dockerHelper, err = NewDockerCmdlineHelper(); err != nil {
		return nil, errRetFunc()
	}
	// Now parse the current system
	return composition, nil
}

// Up brings up all containers
func (c *Composition) Up() error {
	if _, err := c.issueCommand([]string{"up", "--force-recreate", "-d"}); err != nil {
		return fmt.Errorf("Error bringing up docker containers using compose yaml '%s':  %s", c.composeFilesYaml, err)
	}
	return nil
}


func parseComposeFilesArg(composeFileArgs string) []string {
	var args []string
	for _, f := range strings.Fields(composeFileArgs) {
		args = append(args, []string{"-f", f}...)
	}
	return args
}

func (c *Composition) getFileArgs() []string {
	return parseComposeFilesArg(c.composeFilesYaml)
}

// GetContainerIDs returns the container IDs for the composition (NOTE: does NOT include those defined outside composition, eg. chaincode containers)
func (c *Composition) GetContainerIDs() (containerIDs []string, err error) {
	var cmdOutput []byte
	if cmdOutput, err = c.issueCommand([]string{"ps", "-q"}); err != nil {
		return nil, fmt.Errorf("Error getting container IDs for project '%s':  %s", c.projectName, err)
	}
	containerIDs = splitDockerCommandResults(string(cmdOutput))
	return containerIDs, err
}

func (c *Composition) refreshContainerList() (err error) {
	var thisProjectsContainers []docker.APIContainers
	if thisProjectsContainers, err = c.dockerClient.ListContainers(docker.ListContainersOptions{All: true, Filters: map[string][]string{"name": {c.projectName}}}); err != nil {
		return fmt.Errorf("Error refreshing container list for project '%s':  %s", c.projectName, err)
	}
	c.apiContainers = thisProjectsContainers
	return err
}

func (c *Composition) issueCommand(args []string) (_ []byte, err error) {

	var cmdOut []byte
	errRetFunc := func() error {
		return fmt.Errorf("Error issuing command to docker-compose with args '%s':  %s (%s)", args, err, string(cmdOut))
	}
	var cmdArgs []string
	cmdArgs = append(cmdArgs, c.getFileArgs()...)
	cmdArgs = append(cmdArgs, args...)
	cmd := exec.Command(dockerComposeCommand, cmdArgs...) //nolint: gosec
	cmd.Dir = c.dir
	if cmdOut, err = cmd.CombinedOutput(); err != nil {
		return cmdOut, errRetFunc()
	}

	// Reparse Container list
	if err = c.refreshContainerList(); err != nil {
		return nil, errRetFunc()
	}
	return cmdOut, err
}

// Decompose decompose the composition.  Will also remove any containers with the same projectName prefix (eg. chaincode containers)
func (c *Composition) Decompose() (output string, err error) {
	var outputBytes []byte
	//var containers []string
	_, err = c.issueCommand([]string{"stop"})
	if err != nil {
		log.Fatal(err)
	}
	outputBytes, err = c.issueCommand([]string{"rm", "-f"})
	// Now remove associated chaincode containers if any
	containerErr := c.dockerHelper.RemoveContainersWithNamePrefix(c.projectName)
	if containerErr != nil {
		log.Fatal(containerErr)
	}
	return string(outputBytes), err
}

// GenerateLogs to file
func (c *Composition) GenerateLogs() error {
	outputBytes, err := c.issueCommand([]string{"logs"})
	if err != nil {
		return err
	}
	err = ioutil.WriteFile("docker-compose.log", outputBytes, 0775)
	return err
}

// GetAPIContainerForComposeService return the docker.APIContainers with the supplied composeService name.
func (c *Composition) GetAPIContainerForComposeService(composeService string) (apiContainer *docker.APIContainers, err error) {
	for _, apiContainer := range c.apiContainers {
		if currComposeService, ok := apiContainer.Labels["com.docker.compose.service"]; ok {
			if currComposeService == composeService {
				return &docker.APIContainers{
					ID:         apiContainer.ID,
					Image:      apiContainer.Image,
					Command:    apiContainer.Command,
					Created:    apiContainer.Created,
					State:      apiContainer.State,
					Status:     apiContainer.Status,
					Ports:      apiContainer.Ports,
					SizeRw:     apiContainer.SizeRw,
					SizeRootFs: apiContainer.SizeRootFs,
					Names:      apiContainer.Names,
					Labels:     apiContainer.Labels,
					Networks:   apiContainer.Networks,
					Mounts:     apiContainer.Mounts,
				}, nil
			}
		}
	}
	return nil, fmt.Errorf("Could not find container with compose service '%s'", composeService)
}

// GetIPAddressForComposeService returns the IPAddress of the container with the supplied composeService name.
func (c *Composition) GetIPAddressForComposeService(composeService string) (ipAddress string, err error) {
	errRetFunc := func() error {
		return fmt.Errorf("Error getting IPAddress for compose service '%s':  %s", composeService, err)
	}
	var apiContainer *docker.APIContainers
	if apiContainer, err = c.GetAPIContainerForComposeService(composeService); err != nil {
		return "", errRetFunc()
	}
	// Now get the IPAddress
	return apiContainer.Networks.Networks["bridge"].IPAddress, nil
}

// GenerateBytesUUID returns a UUID based on RFC 4122 returning the generated bytes
func GenerateBytesUUID() []byte {
	uuid := make([]byte, 16)
	_, err := io.ReadFull(rand.Reader, uuid)
	if err != nil {
		panic(fmt.Sprintf("Error generating UUID: %s", err))
	}

	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80

	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40

	return uuid
}

