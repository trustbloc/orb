[![Release](https://img.shields.io/github/release/trustbloc/orb.svg?style=flat-square)](https://github.com/trustbloc/orb/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/orb/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/orb)

[![Build Status](https://github.com/trustbloc/orb/actions/workflows/build.yml/badge.svg)](https://github.com/trustbloc/orb/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/trustbloc/orb/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/orb)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/orb)](https://goreportcard.com/report/github.com/trustbloc/orb)
# orb DID Method

Orb implements the following specifications: [did:orb](https://trustbloc.github.io/did-method-orb/),
[Activity Anchors](https://trustbloc.github.io/activityanchors/). The did:orb method is based on the
[Sidetree](https://identity.foundation/sidetree/spec/) specification and Activity Anchors is based on the
[ActivityPub](https://www.w3.org/TR/activitypub/) and [ActivityStreams](https://www.w3.org/TR/activitystreams-core/)
specifications.

Please see [Read the Docs](https://trustbloc.readthedocs.io/en/latest/orb/index.html)
for more details on Orb.

## Build

The project is built using _make_. The BDD test suite can be run with `make bdd-test`. This command builds the Orb images and runs the
integration tests.

## Run

To run Orb outside of _make_, you can use _docker-compose_:

1. `cd test/bdd/fixtures/`
2. `docker-compose up`
This starts the Orb nodes and all dependent containers (wait for containers to start for about 15-20 seconds)

A full set of integration tests is included, which demonstrate all the features of Orb, including adding followers/witnesses and
creating/resolving sample DIDs. (These are located in ./test/bdd/features.) After Orb is started (using the instructions above) you may run the tests as follows:
1. `cd test/bdd`
2. `DISABLE_COMPOSITION=true go test`

(Note that _orb_domain_backup_and_restore_ test requires that
[MongoDB Tools](https://www.mongodb.com/docs/database-tools/installation/installation/)
is installed and _vct_backup_and_restore_ test requires that Command Line Tools, part of [PostgreSQL](https://www.enterprisedb.com/downloads/postgres-postgresql-downloads) is installed.)

You can run individual tests using the -run option, for example:

`DISABLE_COMPOSITION=true go test -run concurrent_requests_scenario`

After the tests have run, you may resolve a DID by hitting the endpoint: https://localhost:48326/sidetree/v1/identifiers/{did}, where {did}
can be chosen from the variety of DIDs in the BDD test console output. It will look like this: did:orb:EiBQyuTmdDYoVWD1GgmM1lLG5wY_9zZNzC0DE-VY3Ska2Q.

You can hit various REST endpoints to discover information about Orb. For example:

- Domain's public key: `https://localhost:48326/.well-known/did.json`
- Discovery configuration: `https://localhost:48326/.well-known/did-orb`

(A complete list of endpoints is documented [here](https://trustbloc.readthedocs.io/en/latest/orb/restendpoints/index.html).)

To bring everything down run `docker-compose down`

## Configuration

To get help about startup options use the following command (don't forget to build Orb (`make orb`) before starting it):

```$ ./.build/bin/orb start -h```

The output should be similar to this:

```
Start orb-server

Usage:
  orb-server start [flags]

Flags:
  -P, --activitypub-page-size string                         The maximum page size for an ActivityPub collection or ordered collection. Alternatively, this can be set with the following environment variable: ACTIVITYPUB_PAGE_SIZE
  -o, --allowed-origins stringArray                          Allowed origins for this did method. Alternatively, this can be set with the following environment variable: ALLOWED_ORIGINS
  -d, --anchor-credential-domain string                      Anchor credential domain (required). Alternatively, this can be set with the following environment variable: ANCHOR_CREDENTIAL_DOMAIN
  -i, --anchor-credential-issuer string                      Anchor credential issuer (required). Alternatively, this can be set with the following environment variable: ANCHOR_CREDENTIAL_ISSUER
  -g, --anchor-credential-url string                         Anchor credential url (required). Alternatively, this can be set with the following environment variable: ANCHOR_CREDENTIAL_URL
      --anchor-data-uri-media-type string                    The media type for data URIs in an anchor Linkset. Possible values are 'application/json' and 'application/gzip;base64'. If 'application/json' is specified then the content of the data URIs in the anchor LInkset are encoded as an escaped JSON string. If 'application/gzip;base64' is specified then the content is compressed with gzip and base64 encoded (default is 'application/gzip;base64').Alternatively, this can be set with the following environment variable: ANCHOR_DATA_URI_MEDIA_TYPE
      --anchor-status-in-process-grace-period string         The period in which witnesses will not be re-selected for 'in-process' anchors.Defaults to 1m if not set. Alternatively, this can be set with the following environment variable: ANCHOR_STATUS_IN_PROCESS_GRACE_PERIOD
      --anchor-status-monitoring-interval string             The interval in which 'in-process' anchors are monitored to ensure that they will be witnessed(completed) as per policy.Defaults to 5s if not set. Alternatively, this can be set with the following environment variable: ANCHOR_STATUS_MONITORING_INTERVAL
      --apclient-cache-Expiration string                     The expiration time of an ActivityPub service and public key cache. Alternatively, this can be set with the following environment variable: ACTIVITYPUB_CLIENT_CACHE_EXPIRATION
      .
      .
      .
```

A complete list of required and optional parameters is documented
[here](https://trustbloc.readthedocs.io/en/latest/orb/parameters.html#startup-parameters).

The minimal configuration to run a service is:

```./.build/bin/orb start --host-url="0.0.0.0:7890" --cas-type=local --external-endpoint=http://localhost:7890 --did-namespace=test --database-type=mem --kms-secrets-database-type=mem --anchor-credential-domain=http://localhost:7890 --anchor-credential-issuer=http://localhost:7890 --anchor-credential-url=http://localhost:7890/vc --anchor-credential-signature-suite=Ed25519Signature2020```

## Databases

The following databases are supported:
* MongoDB
* CouchDB
* Memory (the in-memory database should only be used for demos)

## Contributing

Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/master/CONTRIBUTING.md) for more information.

## License

Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
