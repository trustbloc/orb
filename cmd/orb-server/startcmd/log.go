/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package startcmd

import "github.com/trustbloc/edge-core/pkg/log"

const (
	// LogLevelFlagName is the flag name used for setting the default log level.
	LogLevelFlagName = "log-level"
	// LogLevelEnvKey is the env var name used for setting the default log level.
	LogLevelEnvKey = "LOG_LEVEL"
	// LogLevelFlagShorthand is the shorthand flag name used for setting the default log level.
	LogLevelFlagShorthand = "l"
	// LogLevelPrefixFlagUsage is the usage text for the log level flag.
	LogLevelPrefixFlagUsage = "Sets logging levels for individual modules as well as the default level. `+" +
		"`The format of the string is as follows: module1=level1:module2=level2:defaultLevel. `+" +
		"`Supported levels are: CRITICAL, ERROR, WARNING, INFO, DEBUG." +
		"`Example: metrics=INFO:nodeinfo=WARNING:activitypub_store=INFO:DEBUG. `+" +
		`Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be ` +
		"set with the following environment variable: " + LogLevelEnvKey
)

const logSpecErrorMsg = `Invalid log spec. It needs to be in the following format: "ModuleName1=Level1` +
	`:ModuleName2=Level2:ModuleNameN=LevelN:AllOtherModuleDefaultLevel"
Valid log levels: critical,error,warn,info,debug
Error: %s`

// setLogLevels sets the log levels for individual modules as well as the default level.
func setLogLevels(logger log.Logger, logSpec string) {
	if err := log.SetSpec(logSpec); err != nil {
		logger.Warnf(logSpecErrorMsg, err.Error())

		log.SetLevel("", log.INFO)
	}
}
