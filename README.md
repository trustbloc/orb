[![Release](https://img.shields.io/github/release/trustbloc/orb.svg?style=flat-square)](https://github.com/trustbloc/orb/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/orb/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/orb)

[![Build Status](https://github.com/trustbloc/orb/actions/workflows/build.yml/badge.svg)](https://github.com/trustbloc/orb/actions/workflows/build.yml)
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

In order to start creating DIDs you'll need to set up the Orb services' collection of witnesses and followers.

A service may 'invite' another service to 'witness' a verifiable credential. The originating service creates a verifiable
credential and 'offers' it to its witnesses (see https://trustbloc.github.io/did-method-orb/#offer-activity). A witness adds the
verifiable credential to its own ledger (VCT) and sends back a proof (see https://trustbloc.github.io/did-method-orb/#like-activity).
Once the originating service receives a sufficient number of proofs, it creates an anchor credential from which DID documents are created.
The anchor credential is then announced to the service's followers.

A witness is invited using the 'InviteWitness' ActivityPub activity. The following example shows the service at orb.domain1.com inviting
the service at orb.domain2.com to be a witness. This is accomplished by posting the following activity to orb.domain1.com's outbox,
https://orb.domain1.com/services/orb/outbox (if running outside of Docker then use https://localhost:48326/services/orb/outbox):

```json
{
  "@context": [
    "https://www.w3.org/ns/activitystreams",
    "https://trustbloc.github.io/did-method-orb/contexts/anchor/v1"
  ],
  "actor": "https://orb.domain1.com/services/orb",
  "object": "https://orb.domain2.com/services/orb",
  "to": "https://orb.domain2.com/services/orb",
  "type": "InviteWitness"
}
```

A service requests to follow another service using the 'Follow' activity. The following example shows the service at orb.domain1.com requesting
to follow the service at orb.domain2.com. This is accomplished by posting the following activity to https://orb.domain1.com/services/orb/outbox:

```json
{
  "@context": "https://www.w3.org/ns/activitystreams",
  "actor": "https://orb.domain1.com/services/orb",
  "object": "https://orb.domain2.com/services/orb",
  "to": "https://orb.domain2.com/services/orb",
  "type": "Follow"
}
```

Once the followers and witnesses are set up, you may start creating/resolving DIDs!

A full set of integration tests are included, which demonstrate all the features of Orb, including adding followers/witnesses and
creating/resolving sample DIDs. After Orb is started (using the instructions above) you may run the tests as follows:
1. `cd test/bdd`
2. `DISABLE_COMPOSITION=true go test`

After the tests have run, you may resolve a DID by hitting the endpoint: https://localhost:48326/sidetree/v1/identifiers/{did}, where {did}
can be chosen from the variety of DIDs in the BDD test console output. It will look like this: did:orb:EiBQyuTmdDYoVWD1GgmM1lLG5wY_9zZNzC0DE-VY3Ska2Q.

Domain's public key:
https://localhost:48326/.well-known/did.json

Discovery configuration:
https://localhost:48326/.well-known/did-orb

To bring everything down run `docker-compose down`

## Contributing

Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/master/CONTRIBUTING.md) for more information.

## License

Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
