/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"fmt"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	"github.com/trustbloc/orb/pkg/httpserver"
)

var logger = logrus.New()

var config = viper.New()

func main() {
	config.SetEnvPrefix("ORB")
	config.AutomaticEnv()
	config.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	logger.Info("starting sidetree node...")

	restSvc := httpserver.New(
		getListenURL(),
		config.GetString("tls.certificate"),
		config.GetString("tls.key"),
		config.GetString("api.token"),
	)

	if err := restSvc.Start(); err != nil {
		panic(err)
	}
}

func getListenURL() string {
	host := config.GetString("host")
	if host == "" {
		host = "0.0.0.0"
	}

	port := config.GetInt("port")
	if port == 0 {
		panic("port is not set")
	}

	return fmt.Sprintf("%s:%d", host, port)
}
