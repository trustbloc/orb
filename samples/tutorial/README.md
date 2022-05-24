# Getting Started

## Setup

Install Docker Desktop from here: https://docs.docker.com/get-docker/.

Clone the orb project:

```commandline
git clone git@github.com:trustbloc/orb.git
```

Start two Orb instances (orb1.local and orb2.local) and a command-line image:

```commandline
cd orb/test/bdd/fixtures/tutorial

docker-compose up
```

In another terminal, open an interactive Docker shell:

```commandline
docker exec -ti cli /bin/bash

cd ./orb
```

## Create and Resolve DIDs

Query non-existing DID:

```commandline
orb-cli did resolve --did-uri=did:orb:http:orb1.local:uAAA:EiBFejklGvpC6hn--gZEoiDnEaeineV8xP7p0AcH1-N33A --verify-resolution-result-type=all
```

Create a DID at orb1:

```commandline
orb-cli did create --domain=http://orb1.local --publickey-file=./create_publickeys.json --service-file=./create_services.json --recoverykey-file=./recover_publickey.pem --updatekey-file=./update_publickey.pem --did-anchor-origin=http://orb1.local | jq

export DID_SUFFIX=
```

Resolve the un-anchored DID at orb1:

```commandline
orb-cli did resolve --domain=http://orb1.local --did-uri=did:orb:uAAA:${DID_SUFFIX} --verify-resolution-result-type=all | jq
```

Get hash of anchor from the _resolve_ response (from the "canonicalId" field in the metadata) and set the ANCHOR_HASH environment variable:

```commandline
export ANCHOR_HASH=
```

Resolve the canonical DID at orb1:

```commandline
orb-cli did resolve --domain=http://orb1.local --did-uri=did:orb:${ANCHOR_HASH}:${DID_SUFFIX} --verify-resolution-result-type=all | jq
```

Resolve a discoverable DID at orb1 (using the hint embedded in the DID):

```commandline
orb-cli did resolve --did-uri=did:orb:http:orb1.local:uAAA:${DID_SUFFIX} --verify-resolution-result-type=all | jq
```

Resolve the DID at orb2. These should return 'not found' since orb2 is not following orb1:

```commandline
orb-cli did resolve --sidetree-url-resolution=http://orb2.local/sidetree/v1/identifiers --did-uri=did:orb:uAAA:${DID_SUFFIX} --verify-resolution-result-type=all | jq

orb-cli did resolve --sidetree-url-resolution=http://orb2.local/sidetree/v1/identifiers --did-uri=did:orb:${ANCHOR_HASH}:${DID_SUFFIX}  --verify-resolution-result-type=all | jq
```

Resolve discoverable DID at orb2. This should return 'not found' but when we wait
a while it should be available at orb2 since replication should have been triggered:

```commandline
orb-cli did resolve --sidetree-url-resolution=http://orb2.local/sidetree/v1/identifiers --did-uri=did:orb:http:orb1.local:${ANCHOR_HASH}:${DID_SUFFIX}  --verify-resolution-result-type=all | jq
```

Resolve the same DID at orb2. This should return the DID document:

```commandline
orb-cli did resolve --sidetree-url-resolution=http://orb2.local/sidetree/v1/identifiers --did-uri=did:orb:${ANCHOR_HASH}:${DID_SUFFIX}  --verify-resolution-result-type=all | jq
```

## Follow Orb Domain

Have orb2 be a follower of orb1:

```commandline
orb-cli follower --outbox-url=http://orb2.local/services/orb/outbox --actor=http://orb2.local/services/orb --to http://orb1.local/services/orb --action=Follow

curl -s "http://orb2.local/services/orb/outbox?page=true&page-num=0" | jq

curl -s "http://orb2.local/services/orb/inbox?page=true&page-num=0" | jq
```

Create another DID at orb1:

```commandline
orb-cli did create --domain=http://orb1.local --publickey-file=./create_publickeys.json --service-file=./create_services2.json --recoverykey-file=./recover_publickey.pem --updatekey-file=./update_publickey.pem --did-anchor-origin=http://orb1.local | jq

export DID_SUFFIX=

orb-cli did resolve --did-uri=did:orb:http:orb1.local:uAAA:${DID_SUFFIX} --verify-resolution-result-type=all | jq

export ANCHOR_HASH=
```

Resolve canonical at orb2:

```commandline
orb-cli did resolve --domain=http://orb2.local --did-uri=did:orb:${ANCHOR_HASH}:${DID_SUFFIX} --verify-resolution-result-type=all | jq
```

Look at inbox:

```commandline
curl -s "http://orb2.local/services/orb/inbox?page=true&page-num=0" | jq
```

Update the DID:

```commandline
orb-cli did update --domain=http://orb1.local --did-uri=did:orb:${ANCHOR_HASH}:${DID_SUFFIX} --add-publickey-file=./update_publickeys.json --signingkey-file=./update_privatekey.pem --nextupdatekey-file=./nextupdate_publickey.pem --tls-systemcertpool=true
```

Resolve the DID on orb1:

```commandline
orb-cli did resolve --domain=http://orb1.local --did-uri=did:orb:${ANCHOR_HASH}:${DID_SUFFIX} --verify-resolution-result-type=all | jq
```

Resolve the DID on orb2:

```commandline
orb-cli did resolve --domain=http://orb1.local --did-uri=did:orb:${ANCHOR_HASH}:${DID_SUFFIX} --verify-resolution-result-type=all | jq
```
