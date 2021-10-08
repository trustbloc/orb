[![Release](https://img.shields.io/github/release/trustbloc/orb.svg?style=flat-square)](https://github.com/trustbloc/orb/releases/latest)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://raw.githubusercontent.com/trustbloc/orb/main/LICENSE)
[![Godocs](https://img.shields.io/badge/godoc-reference-blue.svg)](https://godoc.org/github.com/trustbloc/orb)

[![Build Status](https://github.com/trustbloc/orb/actions/workflows/build.yml/badge.svg)](https://github.com/trustbloc/orb/actions/workflows/build.yml)
[![codecov](https://codecov.io/gh/trustbloc/orb/branch/main/graph/badge.svg)](https://codecov.io/gh/trustbloc/orb)
[![Go Report Card](https://goreportcard.com/badge/github.com/trustbloc/orb)](https://goreportcard.com/report/github.com/trustbloc/orb)
# orb DID Method

## Build

The project is built using `make`. 

The BDD test suite can be run via `make bdd-test`.

## Run

To run Orb nodes you can use `docker-compose`.

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
    "https://w3id.org/activityanchors/v1"
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

## Configuration

To get help about startup options use the following command:

```$ ./.build/bin/orb start -h```
The output should be similar to this:

NOTE: Do not forget to build (`make orb `) a service before starting it.
```
Start orb-server

Usage:
  orb-server start [flags]

Flags:
  -P, --activitypub-page-size string                The maximum page size for an ActivityPub collection or ordered collection. Alternatively, this can be set with the following environment variable: ACTIVITYPUB_PAGE_SIZE
  -o, --allowed-origins stringArray                 Allowed origins for this did method. Alternatively, this can be set with the following environment variable: ALLOWED_ORIGINS
  -d, --anchor-credential-domain string             Anchor credential domain (required). Alternatively, this can be set with the following environment variable: ANCHOR_CREDENTIAL_DOMAIN
  -i, --anchor-credential-issuer string             Anchor credential issuer (required). Alternatively, this can be set with the following environment variable: ANCHOR_CREDENTIAL_ISSUER
  -z, --anchor-credential-signature-suite string    Anchor credential signature suite (required). Alternatively, this can be set with the following environment variable: ANCHOR_CREDENTIAL_SIGNATURE_SUITE
  -g, --anchor-credential-url string                Anchor credential url (required). Alternatively, this can be set with the following environment variable: ANCHOR_CREDENTIAL_URL
  -A, --auth-tokens stringArray                     Authorization tokens.
  -D, --auth-tokens-def stringArray                 Authorization token definitions.
  -b, --batch-writer-timeout string                 Maximum time (in millisecond) in-between cutting batches.Alternatively, this can be set with the following environment variable: BATCH_WRITER_TIMEOUT
  -c, --cas-type string                             The type of the Content Addressable Storage (CAS). Supported options: local, ipfs. For local, the storage provider specified by database-type will be used. For ipfs, the node specified by ipfs-url will be used. This is a required parameter. Alternatively, this can be set with the following environment variable: CAS_TYPE
      --cid-version string                          The version of the CID format to use for generating CIDs. Supported options: 0, 1. If not set, defaults to 1.Alternatively, this can be set with the following environment variable: CID_VERSION (default "1")
      --database-prefix string                      An optional prefix to be used when creating and retrieving underlying databases. Alternatively, this can be set with the following environment variable: DATABASE_PREFIX
  -t, --database-type string                        The type of database to use for everything except key storage. Supported options: mem, couchdb, mongodb. Alternatively, this can be set with the following environment variable: DATABASE_TYPE
  -v, --database-url string                         The URL of the database. Not needed if using memstore. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: DATABASE_URL
      --database-timeout string                     The timeout for database requests. For example, '30s' for a 30 second timeout. Currently this setting only applies if you're using MongoDB. Alternatively, this can be set with the following environment variable: DATABASE_TIMEOUT
  -a, --did-aliases stringArray                     Aliases for this did method. Alternatively, this can be set with the following environment variable: DID_ALIASES
  -n, --did-namespace string                        DID Namespace.Alternatively, this can be set with the following environment variable: DID_NAMESPACE
      --discovery-domain string                     Discovery domain for this domain. Format: HostName
      --discovery-domains stringArray               Discovery domains. Alternatively, this can be set with the following environment variable: DISCOVERY_DOMAINS
      --discovery-minimum-resolvers string          Discovery minimum resolvers number.Alternatively, this can be set with the following environment variable: DISCOVERY_MINIMUM_RESOLVERS
      --discovery-vct-domains stringArray           Discovery vctdomains. Alternatively, this can be set with the following environment variable: DISCOVERY_VCT_DOMAINS
      --enable-create-document-store string         Set to "true" to enable create document store. Used for resolving unpublished created documents.Alternatively, this can be set with the following environment variable: CREATE_DOCUMENT_STORE_ENABLED
      --enable-dev-mode string                      Set to "true" to enable dev mode. Alternatively, this can be set with the following environment variable: DEV_MODE_ENABLED (default "false")
      --enable-did-discovery string                 Set to "true" to enable did discovery. Alternatively, this can be set with the following environment variable: DID_DISCOVERY_ENABLED
  -p, --enable-http-signatures string               Set to "true" to enable HTTP signatures in ActivityPub. Alternatively, this can be set with the following environment variable: HTTP_SIGNATURES_ENABLED
  -e, --external-endpoint string                    External endpoint that clients use to invoke services. This endpoint is used to generate IDs of anchor credentials and ActivityPub objects and should be resolvable by external clients. Format: HostName[:Port].
  -h, --help                                        help for start
  -u, --host-url string                             URL to run the orb-server instance on. Format: HostName:Port.
  -T, --ipfs-timeout string                         The timeout for IPFS requests. For example, '30s' for a 30 second timeout. Alternatively, this can be set with the following environment variable: IPFS_TIMEOUT
  -r, --ipfs-url string                             Enables IPFS support. If set, this Orb server will use the node at the given URL. To use the public ipfs.io node, set this to https://ipfs.io (or http://ipfs.io). If using ipfs.io, then the CAS type flag must be set to local since the ipfs.io node is read-only. If the URL doesnt include a scheme, then HTTP will be used by default. Alternatively, this can be set with the following environment variable: IPFS_URL
      --key-id string                               Key ID (ED25519Type). Alternatively, this can be set with the following environment variable: ORB_KEY_ID
      --kms-endpoint string                         Remote KMS URL. Alternatively, this can be set with the following environment variable: ORB_KMS_ENDPOINT
      --kms-secrets-database-prefix string          An optional prefix to be used when creating and retrieving the underlying KMS secrets database. Alternatively, this can be set with the following environment variable: KMSSECRETS_DATABASE_PREFIX
  -k, --kms-secrets-database-type string            The type of database to use for storage of KMS secrets. Supported options: mem, couchdb, mongodb. Alternatively, this can be set with the following environment variable: KMSSECRETS_DATABASE_TYPE
  -s, --kms-secrets-database-url string             The URL of the database. Not needed if using memstore. For CouchDB, include the username:password@ text if required. Alternatively, this can be set with the following environment variable: DATABASE_URL
      --kms-store-endpoint string                   Remote KMS URL. Alternatively, this can be set with the following environment variable: ORB_KMS_STORE_ENDPOINT
  -l, --log-level string                            Logging level to set. Supported options: CRITICAL, ERROR, WARNING, INFO, DEBUG.Defaults to info if not set. Setting to debug may adversely impact performance. Alternatively, this can be set with the following environment variable: LOG_LEVEL
  -w, --max-witness-delay string                    Maximum witness response time (in seconds). Alternatively, this can be set with the following environment variable: MAX_WITNESS_DELAY
  -C, --mq-max-connection-subscription string       The maximum number of subscriptions per connection. Alternatively, this can be set with the following environment variable: MQ_MAX_CONNECTION_SUBSCRIPTIONS
  -O, --mq-op-pool string                           The size of the operation queue subscriber pool. If 0 then a pool will not be created. Alternatively, this can be set with the following environment variable: MQ_OP_POOL
  -q, --mq-url string                               The URL of the message broker. Alternatively, this can be set with the following environment variable: MQ_URL
  -R, --nodeinfo-refresh-interval string            The interval for refreshing NodeInfo data. For example, '30s' for a 30 second interval. Alternatively, this can be set with the following environment variable: NODEINFO_REFRESH_INTERVAL
      --private-key string                          Private Key base64 (ED25519Type). Alternatively, this can be set with the following environment variable: ORB_PRIVATE_KEY
      --replicate-local-cas-writes-in-ipfs string   If enabled, writes to the local CAS will also be replicated in IPFS. This setting only takes effect if this server has both a local CAS and IPFS enabled. If the IPFS node is set to ipfs.io, then this setting will be disabled since ipfs.io does not support writes. Supported options: false, true. Defaults to false if not set. Alternatively, this can be set with the following environment variable: REPLICATE_LOCAL_CAS_WRITES_IN_IPFS (default "false")
      --secret-lock-key-path string                 The path to the file with key to be used by local secret lock. If missing noop service lock is used. Alternatively, this can be set with the following environment variable: ORB_SECRET_LOCK_KEY_PATH
  -f, --sign-with-local-witness string              Always sign with local witness flag (default true). Alternatively, this can be set with the following environment variable: SIGN_WITH_LOCAL_WITNESS
      --sync-timeout string                         Total time in seconds to resolve config values. Alternatively, this can be set with the following environment variable: ORB_SYNC_TIMEOUT (default "1")
  -y, --tls-certificate string                      TLS certificate for ORB server. Alternatively, this can be set with the following environment variable: ORB_TLS_CERTIFICATE
  -x, --tls-key string                              TLS key for ORB server. Alternatively, this can be set with the following environment variable: ORB_TLS_KEY
      --vct-url string                              Verifiable credential transparency URL.

```

Each parameter has a description. It should not be hard to start a service.

Minimal configuration to run a service is:

```./.build/bin/orb start --host-url="0.0.0.0:7890" --cas-type=local --external-endpoint=http://localhost:7890 --did-namespace=test --database-type=mem --kms-secrets-database-type=mem --anchor-credential-domain=http://localhost:7890 --anchor-credential-issuer=http://localhost:7890 --anchor-credential-url=http://localhost:7890/vc --anchor-credential-signature-suite=Ed25519Signature2018```

## Databases

Orb uses the Aries generic storage interface for storing data.
Backup should be done similarly to other TrustBloc projects.
In Orb we support the following databases:
* CouchDB
* MongoDB
* Memory (backup is not supported)

Use the database-specific command to get all databases and filter them by the `DATABASE_PREFIX` and `KMSSECRETS_DATABASE_PREFIX` environment variables.

NOTE: The service might use two different databases. In that case, do the procedure per-database and filter the output only by one prefix.
`DATABASE_PREFIX` for `DATABASE_URL` and `KMSSECRETS_DATABASE_PREFIX` for `KMSSECRETS_DATABASE_URL`.

For instance, to get all databases for CouchDB use the following command:
```
curl -X GET http://admin:password@127.0.0.1:5984/_all_dbs
```
Output:
```
["_replicator","_users","cas_store","didanchor","jsonldcontexts","kmsdb","operation","orb-config","orb_db__/services/orbactivity","orb_db__/services/orbactor","orb_db__/services/orbanchor_cred","orb_db__/services/orbfollower","orb_db__/services/orbfollowing","orb_db__/services/orbinbox","orb_db__/services/orblike","orb_db__/services/orbliked","orb_db__/services/orboutbox","orb_db__/services/orbpublic_outbox","orb_db__/services/orbshare","orb_db__/services/orbwitness","orb_db__/services/orbwitnessing","orb_db_cas_store","orb_db_didanchor","orb_db_jsonldcontexts","orb_db_kmsdb","orb_db_monitoring","orb_db_operation","orb_db_orb-config","orb_db_vcstatus","orb_db_verifiable","orb_db_witness","orb_sec_db_kmsdb","vcstatus","verifiable","witness"]
```

Then, filter databases from the output above by `DATABASE_PREFIX` and `KMSSECRETS_DATABASE_PREFIX` env.
Databases we need to backup are `orb_sec_db_kmsdb`, `orb_db__/services/orbactivity`, `orb_db__/services/orbactor`, `orb_db__/services/orbanchor_cred`, `orb_db__/services/orbfollower`, `orb_db_monitoring`,`orb_db_operation`,`orb_db_orb-config` etc.
Make a backup according to CouchDB documentation.

## Contributing

Thank you for your interest in contributing. Please see our [community contribution guidelines](https://github.com/trustbloc/community/blob/master/CONTRIBUTING.md) for more information.

## License

Apache License, Version 2.0 (Apache-2.0). See the [LICENSE](LICENSE) file.
