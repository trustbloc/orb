package rabbitmqtestutil

import (
	"fmt"
	"log"
	"strings"
	"sync/atomic"

	dctest "github.com/ory/dockertest/v3"
	dc "github.com/ory/dockertest/v3/docker"
)

const startingPort = 5672

var currentPort uint32 = startingPort //nolint:gochecknoglobals

// StartRabbitMQ starts a RabbitMQ Docker container. The connection URI is returned,
// as well as a function that should be invoked to stop the Docker container when it is
// no longer required.
func StartRabbitMQ() (mqURI string, stop func()) {
	pool, rabbitMQResource, mqURI := startRabbitMQContainer()

	return mqURI, func() {
		if pool != nil && rabbitMQResource != nil {
			err := pool.Purge(rabbitMQResource)
			if err != nil {
				panic(fmt.Sprintf("Failed to purge RabbitMQ resource: %s", err.Error()))
			}
		}
	}
}

func startRabbitMQContainer() (*dctest.Pool, *dctest.Resource, string) {
	pool, err := dctest.NewPool("")
	if err != nil {
		panic(fmt.Sprintf("Failed to create new pool: %s", err.Error()))
	}

	const maxAttempts = 10

	for i := 0; i < maxAttempts; i++ {
		// Always use a new port since the tests periodically complain about port already in use.
		port := newPort()

		resource, err := pool.RunWithOptions(&dctest.RunOptions{
			Repository: "rabbitmq",
			Tag:        "3-management-alpine",
			PortBindings: map[dc.Port][]dc.PortBinding{
				"5672/tcp": {
					{HostIP: "", HostPort: fmt.Sprintf("%d", port)},
				},
			},
		})
		if err != nil {
			if strings.Contains(err.Error(), "port is already allocated") {
				log.Println(fmt.Sprintf("Got error. Trying on another port: %s", err.Error()))

				continue
			}

			panic(fmt.Sprintf("Unable to start RabbitMQ Docker container: %s", err.Error()))
		}

		mqURI := fmt.Sprintf("amqp://guest:guest@localhost:%d/", port)

		return pool, resource, mqURI
	}

	panic(fmt.Sprintf("Unable to start RabbitMQ Docker container after %d attempts", maxAttempts))
}

func newPort() uint32 {
	return atomic.AddUint32(&currentPort, 1)
}
