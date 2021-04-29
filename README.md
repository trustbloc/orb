[![Release](https://img.shields.io/github/release/trustbloc/orb.svg?style=flat-square)](https://github.com/trustbloc/orb/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/orb/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/orb)

[![Build Status](https://dev.azure.com/trustbloc/edge/_apis/build/status/trustbloc.orb?branchName=main)](https://dev.azure.com/trustbloc/orb/_build/latest?definitionId=27&branchName=main)
[![codecov](https://codecov.io/gh/trustbloc/orb/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/orb)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/orb)](https://goreportcard.com/report/github.com/trustbloc/orb)
# orb DID Method

## Build

The project is built using make. 

BDD test suit can be run via `make bdd-test`

## Run

To run Orb nodes you can use docker-compose.

First run the docker compose itself via

1. `cd test/bdd/fixtures/`
2. `docker-compose up`
This will start up the Orb nodes (wait for containers to start for about 15-20 seconds)

3. `cd test/bdd`
4. `DISABLE_COMPOSITION=true go test`

Resolve DID: https://localhost:48326/sidetree/v1/identifiers/{did}

You can choose DID from variety of DIDs from BDD test output. It will look like this: did:orb:EiBQyuTmdDYoVWD1GgmM1lLG5wY_9zZNzC0DE-VY3Ska2Q

Domain's public key:
https://localhost:48326/.well-known/did.json

Discovery configuration:
https://localhost:48326/.well-known/did-orb

To bring everything down run `docker-compose down`

## Contributing

Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/master/CONTRIBUTING.md) for more information.

## License

Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
