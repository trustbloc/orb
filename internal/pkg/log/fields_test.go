/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package log

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/trustbloc/logutil-go/pkg/log"
)

//nolint:maintidx
func TestStandardFields(t *testing.T) {
	const module = "test_module"

	u1 := parseURL(t, "https://example1.com")
	u2 := parseURL(t, "https://example2.com")
	u3 := parseURL(t, "https://example3.com")
	hl := parseURL(t, "hl:1234")

	t.Run("json fields 1", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := log.New(module, log.WithStdOut(stdOut), log.WithEncoding(log.JSON))

		now := time.Now()

		query := &mockObject{Field1: "value1", Field2: 1234}

		logger.Info("Some message",
			WithMessageID("msg1"), WithData([]byte(`{"field":"value"}`)),
			WithActorIRI(u1), WithActivityID(u2), WithActivityType("Create"),
			WithServiceIRI(parseURL(t, u2.String())), WithServiceName("service1"),
			WithServiceEndpoint("/services/service1"),
			WithSize(1234), WithCacheExpiration(12*time.Second),
			WithTargetIRI(u1), WithParameter("param1"),
			WithReferenceType("followers"), WithURI(u2), WithURIs(u1, u2),
			WithSenderURL(u1), WithAnchorURI(u3), WithAnchorEventURI(u3),
			WithAcceptListType("follow"),
			WithURLAdditions(u1, u3),
			WithURLDeletions(u1),
			WithRequestURL(u1), WithRequestBody([]byte(`request body`)),
			WithRequestHeaders(map[string][]string{"key1": {"v1", "v2"}, "key2": {"v3"}}),
			WithObjectIRI(u1), WithReferenceIRI(u2),
			WithKeyIRI(u1), WithKeyOwnerIRI(u2), WithKeyType("ed25519"),
			WithCurrentIRI(u1), WithNextIRI(u2),
			WithTotal(12), WithType("type1"), WithQuery(query),
			WithAnchorHash("sfsfsdfsd"), WithMinimum(2), WithSuffix("1234"), WithHashlink(hl.String()),
			WithVerifiableCredential([]byte(`{"id":"https://example.com/vc1"}`)),
			WithVerifiableCredentialID("https://example.com/vc1"),
			WithParent("parent1"), WithParents([]string{"parent1", "parent2"}),
			WithProof([]byte(`{"id":"https://example.com/proof1"}`)),
			WithCreatedTime(now), WithWitnessURI(u1), WithWitnessURIs(u1, u2), WithWitnessPolicy("some policy"),
			WithAnchorOrigin(u1.String()), WithOperationType("Create"), WithCoreIndex("1234"),
		)

		t.Logf(stdOut.String())
		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, `Some message`, l.Msg)
		require.Equal(t, `msg1`, l.MessageID)
		require.Equal(t, `{"field":"value"}`, l.Data)
		require.Equal(t, u1.String(), l.ActorID)
		require.Equal(t, u2.String(), l.ActivityID)
		require.Equal(t, `Create`, l.ActivityType)
		require.Equal(t, `service1`, l.Service)
		require.Equal(t, `/services/service1`, l.ServiceEndpoint)
		require.Equal(t, u2.String(), l.ServiceIri)
		require.Equal(t, 1234, l.Size)
		require.Equal(t, `12s`, l.CacheExpiration)
		require.Equal(t, u1.String(), l.Target)
		require.Equal(t, `param1`, l.Parameter)
		require.Equal(t, `followers`, l.ReferenceType)
		require.Equal(t, u2.String(), l.URI)
		require.Equal(t, []string{u1.String(), u2.String()}, l.URIs)
		require.Equal(t, u3.String(), l.AnchorURI)
		require.Equal(t, u3.String(), l.AnchorEventURI)
		require.Equal(t, `follow`, l.AcceptListType)
		require.Equal(t, []string{u1.String(), u3.String()}, l.Additions)
		require.Equal(t, []string{u1.String()}, l.Deletions)
		require.Equal(t, u1.String(), l.RequestURL)
		require.Equal(t, `request body`, l.RequestBody)
		require.Equal(t, map[string][]string{"key1": {"v1", "v2"}, "key2": {"v3"}}, l.RequestHeaders)
		require.Equal(t, u1.String(), l.ObjectIRI)
		require.Equal(t, u2.String(), l.Reference)
		require.Equal(t, u1.String(), l.KeyID)
		require.Equal(t, u2.String(), l.KeyOwnerID)
		require.Equal(t, "ed25519", l.KeyType)
		require.Equal(t, u1.String(), l.Current)
		require.Equal(t, u2.String(), l.Next)
		require.Equal(t, 12, l.Total)
		require.Equal(t, 2, l.Minimum)
		require.Equal(t, "type1", l.Type)
		require.Equal(t, query, l.Query)
		require.Equal(t, "sfsfsdfsd", l.AnchorHash)
		require.Equal(t, "1234", l.Suffix)
		require.Equal(t, hl.String(), l.Hashlink)
		require.Equal(t, `{"id":"https://example.com/vc1"}`, l.VerifiableCredential)
		require.Equal(t, "https://example.com/vc1", l.VerifiableCredentialID)
		require.Equal(t, "parent1", l.Parent)
		require.Equal(t, []string{"parent1", "parent2"}, l.Parents)
		require.Equal(t, `{"id":"https://example.com/proof1"}`, l.Proof)
		require.Equal(t, now.Format("2006-01-02T15:04:05.000Z0700"), l.CreatedTime)
		require.Equal(t, u1.String(), l.WitnessURI)
		require.Equal(t, []string{u1.String(), u2.String()}, l.WitnessURIs)
		require.Equal(t, "some policy", l.WitnessPolicy)
		require.Equal(t, u1.String(), l.AnchorOrigin)
		require.Equal(t, "Create", l.OperationType)
		require.Equal(t, "1234", l.CoreIndex)
	})

	t.Run("json fields 2", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := log.New(module, log.WithStdOut(stdOut), log.WithEncoding(log.JSON))

		cfg := &mockObject{Field1: "value1", Field2: 1234}
		aoep := &mockObject{Field1: "value11", Field2: 999}
		rr := &mockObject{Field1: "value22", Field2: 777}
		rm := &mockObject{Field1: "value33", Field2: 888}

		logger.Info("Some message",
			WithActorID(u1.String()), WithTarget(u2.String()),
			WithConfig(&mockObject{Field1: "value1", Field2: 1234}),
			WithRequestURLString(u1.String()),
			WithKeyID("key1"), WithURIString(u1.String()),
			WithAnchorEventURIString(u3.String()), WithAnchorURIString(u3.String()),
			WithHashlinkURI(hl), WithParentURI(u1),
			WithProofDocument(map[string]interface{}{"id": "https://example.com/proof1"}),
			WithWitnessURIString(u1.String()), WithWitnessURIStrings(u1.String(), u2.String()),
			WithHash("hash1"), WithAnchorOriginEndpoint(aoep), WithKey("key1"),
			WithCID("cid1"), WithResolvedCID("cid2"), WithAnchorCID("cid3"),
			WithCIDVersion(1), WithMultihash("fsdfervs"), WithCASData([]byte("cas data")),
			WithDomain(u1.String()), WithLink(u2.String()), WithLinks(u1.String(), u2.String()),
			WithTaskMgrInstanceID("12345"), WithRetries(7), WithMaxRetries(12),
			WithSubscriberPoolSize(30), WithTaskMonitorInterval(5*time.Second),
			WithTaskExpiration(10*time.Second), WithDeliveryDelay(3*time.Second),
			WithOperationID("op1"), WithPermitHolder("123"), WithTimeSinceLastUpdate(2*time.Minute),
			WithGenesisTime(1233), WithDID("did:orb:123:456"), WithHRef(u3.String()),
			WithID("id1"), WithResource("res1"), WithResolutionResult(rr),
			WithResolutionModel(rm), WithResolutionEndpoints(u1.String(), u2.String(), u3.String()),
		)

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, `Some message`, l.Msg)
		require.Equal(t, u1.String(), l.ActorID)
		require.Equal(t, u2.String(), l.Target)
		require.Equal(t, cfg, l.Config)
		require.Equal(t, u1.String(), l.RequestURL)
		require.Equal(t, "key1", l.KeyID)
		require.Equal(t, u1.String(), l.URI)
		require.Equal(t, u1.String(), l.URI)
		require.Equal(t, u3.String(), l.AnchorEventURI)
		require.Equal(t, u3.String(), l.AnchorURI)
		require.Equal(t, hl.String(), l.Hashlink)
		require.Equal(t, u1.String(), l.Parent)
		require.Equal(t, `{"id":"https://example.com/proof1"}`, l.Proof)
		require.Equal(t, u1.String(), l.WitnessURI)
		require.Equal(t, []string{u1.String(), u2.String()}, l.WitnessURIs)
		require.Equal(t, "hash1", l.Hash)
		require.Equal(t, aoep, l.AnchorOriginEndpoint)
		require.Equal(t, "key1", l.Key)
		require.Equal(t, "cid1", l.CID)
		require.Equal(t, "cid2", l.ResolvedCID)
		require.Equal(t, "cid3", l.AnchorCID)
		require.Equal(t, 1, l.CIDVersion)
		require.Equal(t, "fsdfervs", l.Multihash)

		casData, err := base64.StdEncoding.DecodeString(l.CASData)
		require.NoError(t, err)
		require.Equal(t, "cas data", string(casData))

		require.Equal(t, u1.String(), l.Domain)
		require.Equal(t, u2.String(), l.Link)
		require.Equal(t, []string{u1.String(), u2.String()}, l.Links)
		require.Equal(t, "12345", l.TaskMgrInstanceID)
		require.Equal(t, 7, l.Retries)
		require.Equal(t, 12, l.MaxRetries)
		require.Equal(t, 30, l.SubscriberPoolSize)
		require.Equal(t, "5s", l.TaskMonitorInterval)
		require.Equal(t, "10s", l.TaskExpiration)
		require.Equal(t, "3s", l.DeliveryDelay)
		require.Equal(t, "op1", l.OperationID)
		require.Equal(t, "123", l.PermitHolder)
		require.Equal(t, "2m0s", l.TimeSinceLastUpdate)
		require.Equal(t, 1233, l.GenesisTime)
		require.Equal(t, "did:orb:123:456", l.DID)
		require.Equal(t, u3.String(), l.HRef)
		require.Equal(t, "id1", l.ID)
		require.Equal(t, "res1", l.Resource)
		require.Equal(t, rr, l.ResolutionResult)
		require.Equal(t, rm, l.ResolutionModel)
		require.Equal(t, []string{u1.String(), u2.String(), u3.String()}, l.ResolutionEndpoints)
	})

	t.Run("json fields 3", func(t *testing.T) {
		stdOut := newMockWriter()

		logger := log.New(module, log.WithStdOut(stdOut), log.WithEncoding(log.JSON))

		metadata := &mockObject{Field1: "meta1", Field2: 7676}
		protocol := &mockObject{Field1: "proto1", Field2: 2314}
		params := &mockObject{Field1: "param1", Field2: 4612}
		op := &mockObject{Field1: "op1", Field2: 9486}
		txn := &mockObject{Field1: "txn1", Field2: 5967}
		jrd := &mockObject{Field1: "jrd1", Field2: 2312}
		logMonitor := &mockObject{Field1: "mon1", Field2: 6732}

		logger.Info("Some message",
			WithMetadata(metadata), WithSidetreeProtocol(protocol), WithOriginActorID(u2.String()), WithTargetIRIs(u2, u3),
			WithHTTPMethod(http.MethodPost), WithSuffixes("suffix1", "suffix2"), WithLocalHashlink(hl.String()),
			WithAuthToken("token1"), WithAuthTokens("token1", "token2"), WithAddress(u1.String()),
			WithAttributedTo(u2.String()), WithAnchorLinkset([]byte(`"linkset":"{}"`)), WithVersion("v1"),
			WithSizeUint64(10), WithMaxSize(20),
			WithParameters(params), WithURL(u1), WithAnchorURIStrings(u1.String(), u2.String()),
			WithOperation(op), WithValue("value1"), WithTaskID("task1"), WithSidetreeTxn(txn),
			WithAnchorLink([]byte(`{"link":"{}"}`)), WithDeliveryAttempts(37), WithProperty("prop1"),
			WithStoreName("store1"), WithIssuer("issuer1"), WithStatus("status1"),
			WithLogURL(u3), WithNamespace("ns1"), WithCanonicalRef("ref1"),
			WithAnchorString("anchor1"), WithJRD(jrd), WithBackoff(5*time.Second), WithTimeout(2*time.Minute),
			WithLogMonitor(logMonitor), WithLogMonitors([]*mockObject{logMonitor, logMonitor}),
			WithMaxTime(time.Hour), WithIndex(3), WithFromIndexUint64(9), WithToIndexUint64(13),
			WithSource("inbox"), WithAge(time.Minute), WithMinAge(10*time.Minute),
		)

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, metadata, l.Metadata)
		require.Equal(t, protocol, l.SidetreeProtocol)
		require.Equal(t, u2.String(), l.OriginActorID)
		require.Equal(t, []string{u2.String(), u3.String()}, l.Targets)
		require.Equal(t, http.MethodPost, l.HTTPMethod)
		require.Equal(t, []string{"suffix1", "suffix2"}, l.Suffixes)
		require.Equal(t, hl.String(), l.LocalHashlink)
		require.Equal(t, "token1", l.AuthToken)
		require.Equal(t, []string{"token1", "token2"}, l.AuthTokens)
		require.Equal(t, u1.String(), l.Address)
		require.Equal(t, u2.String(), l.AttributedTo)
		require.Equal(t, `"linkset":"{}"`, l.AnchorLinkset)
		require.Equal(t, "v1", l.Version)
		require.Equal(t, 10, l.Size)
		require.Equal(t, 20, l.MaxSize)
		require.Equal(t, params, l.Parameters)
		require.Equal(t, u1.String(), l.URL)
		require.Equal(t, []string{u1.String(), u2.String()}, l.AnchorURIs)
		require.Equal(t, op, l.Operation)
		require.Equal(t, "value1", l.Value)
		require.Equal(t, "task1", l.TaskID)
		require.Equal(t, txn, l.SidetreeTxn)
		require.Equal(t, `{"link":"{}"}`, l.AnchorLink)
		require.Equal(t, 37, l.DeliveryAttempts)
		require.Equal(t, "prop1", l.Property)
		require.Equal(t, "store1", l.StoreName)
		require.Equal(t, "issuer1", l.Issuer)
		require.Equal(t, "status1", l.Status)
		require.Equal(t, u3.String(), l.LogURL)
		require.Equal(t, "ns1", l.Namespace)
		require.Equal(t, "ref1", l.CanonicalRef)
		require.Equal(t, "anchor1", l.AnchorString)
		require.Equal(t, jrd, l.JRD)
		require.Equal(t, "5s", l.Backoff)
		require.Equal(t, "2m0s", l.Timeout)
		require.Equal(t, logMonitor, l.LogMonitor)
		require.Equal(t, []*mockObject{logMonitor, logMonitor}, l.LogMonitors)
		require.Equal(t, "1h0m0s", l.MaxTime)
		require.Equal(t, 3, l.Index)
		require.Equal(t, 9, l.FromIndex)
		require.Equal(t, 13, l.ToIndex)
		require.Equal(t, "inbox", l.Source)
		require.Equal(t, "1m0s", l.Age)
		require.Equal(t, "10m0s", l.MinAge)
	})

	t.Run("json fields 4", func(t *testing.T) {
		const logSpec = "module1=DEBUG:INFO"

		stdOut := newMockWriter()

		logger := log.New(module, log.WithStdOut(stdOut), log.WithEncoding(log.JSON))

		logger.Info("Some message",
			WithMaxSizeUInt64(30), WithURLString(u1.String()), WithLogURLString(u3.String()), WithIndexUint64(7),
			WithLogSpec(logSpec),
		)

		l := unmarshalLogData(t, stdOut.Bytes())

		require.Equal(t, 30, l.MaxSize)
		require.Equal(t, u1.String(), l.URL)
		require.Equal(t, u3.String(), l.LogURL)
		require.Equal(t, 7, l.Index)
		require.Equal(t, logSpec, l.LogSpec)
	})
}

type mockObject struct {
	Field1 string `json:"field1"`
	Field2 int    `json:"field2"`
}

type logData struct {
	Level  string `json:"level"`
	Time   string `json:"time"`
	Logger string `json:"logger"`
	Caller string `json:"caller"`
	Msg    string `json:"msg"`
	Error  string `json:"error"`

	MessageID              string              `json:"messageId"`
	Data                   string              `json:"data"`
	ActorID                string              `json:"actorId"`
	ActivityID             string              `json:"activityId"`
	ActivityType           string              `json:"activityType"`
	ServiceIri             string              `json:"serviceIri"`
	Service                string              `json:"service"`
	ServiceEndpoint        string              `json:"serviceEndpoint"`
	Size                   int                 `json:"size"`
	CacheExpiration        string              `json:"cacheExpiration"`
	Target                 string              `json:"target"`
	Parameter              string              `json:"parameter"`
	ReferenceType          string              `json:"referenceType"`
	URI                    string              `json:"uri"`
	URIs                   []string            `json:"uris"`
	Sender                 string              `json:"sender"`
	AnchorURI              string              `json:"anchorUri"`
	AnchorEventURI         string              `json:"anchorEventUri"`
	Config                 *mockObject         `json:"config"`
	AcceptListType         string              `json:"acceptListType"`
	Additions              []string            `json:"additions"`
	Deletions              []string            `json:"deletions"`
	RequestURL             string              `json:"requestUrl"`
	RequestHeaders         map[string][]string `json:"requestHeaders"`
	RequestBody            string              `json:"requestBody"`
	ObjectIRI              string              `json:"objectIri"`
	Reference              string              `json:"reference"`
	KeyID                  string              `json:"keyId"`
	KeyOwnerID             string              `json:"keyOwner"`
	KeyType                string              `json:"keyType"`
	Current                string              `json:"current"`
	Next                   string              `json:"next"`
	Total                  int                 `json:"total"`
	Minimum                int                 `json:"minimum"`
	Type                   string              `json:"type"`
	Query                  *mockObject         `json:"query"`
	AnchorHash             string              `json:"anchorHash"`
	Suffix                 string              `json:"suffix"`
	VerifiableCredential   string              `json:"vc"`
	VerifiableCredentialID string              `json:"vcId"`
	Hashlink               string              `json:"hashlink"`
	Parent                 string              `json:"parent"`
	Parents                []string            `json:"parents"`
	Proof                  string              `json:"proof"`
	CreatedTime            string              `json:"createdTime"`
	WitnessURI             string              `json:"witnessUri"`
	WitnessURIs            []string            `json:"WitnessURIs"` //nolint:tagliatelle
	WitnessPolicy          string              `json:"witnessPolicy"`
	AnchorOrigin           string              `json:"anchorOrigin"`
	OperationType          string              `json:"operationType"`
	CoreIndex              string              `json:"coreIndex"`
	Hash                   string              `json:"hash"`
	AnchorOriginEndpoint   *mockObject         `json:"anchorOriginEndpoint"`
	Key                    string              `json:"key"`
	CID                    string              `json:"cid"`
	ResolvedCID            string              `json:"resolvedCid"`
	AnchorCID              string              `json:"anchorCid"`
	CIDVersion             int                 `json:"cidVersion"`
	Multihash              string              `json:"multihash"`
	CASData                string              `json:"casData"`
	Domain                 string              `json:"domain"`
	Link                   string              `json:"link"`
	Links                  []string            `json:"links"`
	TaskMgrInstanceID      string              `json:"taskMgrInstanceId"`
	Retries                int                 `json:"retries"`
	MaxRetries             int                 `json:"maxRetries"`
	SubscriberPoolSize     int                 `json:"subscriberPoolSize"`
	TaskMonitorInterval    string              `json:"taskMonitorInterval"`
	TaskExpiration         string              `json:"taskExpiration"`
	DeliveryDelay          string              `json:"deliveryDelay"`
	OperationID            string              `json:"operationId"`
	PermitHolder           string              `json:"permitHolder"`
	TimeSinceLastUpdate    string              `json:"timeSinceLastUpdate"`
	GenesisTime            int                 `json:"genesisTime"`
	DID                    string              `json:"did"`
	HRef                   string              `json:"href"`
	ID                     string              `json:"id"`
	Resource               string              `json:"resource"`
	ResolutionResult       *mockObject         `json:"resolutionResult"`
	ResolutionModel        *mockObject         `json:"resolutionModel"`
	ResolutionEndpoints    []string            `json:"resolutionEndpoints"`
	Metadata               *mockObject         `json:"metadata"`
	SidetreeProtocol       *mockObject         `json:"sidetreeProtocol"`
	OriginActorID          string              `json:"originActorId"`
	Targets                []string            `json:"targets"`
	HTTPMethod             string              `json:"httpMethod"`
	Suffixes               []string            `json:"suffixes"`
	LocalHashlink          string              `json:"localHashlink"`
	AuthToken              string              `json:"authToken"`
	AuthTokens             []string            `json:"authTokens"`
	Address                string              `json:"address"`
	AttributedTo           string              `json:"attributedTo"`
	AnchorLinkset          string              `json:"anchorLinkset"`
	Version                string              `json:"version"`
	MaxSize                int                 `json:"maxSize"`
	Parameters             *mockObject         `json:"parameters"`
	URL                    string              `json:"url"`
	AnchorURIs             []string            `json:"anchorURIs"` //nolint:tagliatelle
	Operation              *mockObject         `json:"operation"`
	Value                  string              `json:"value"`
	TaskID                 string              `json:"taskId"`
	SidetreeTxn            *mockObject         `json:"sidetreeTxn"`
	AnchorLink             string              `json:"anchorLink"`
	DeliveryAttempts       int                 `json:"deliveryAttempts"`
	Property               string              `json:"property"`
	StoreName              string              `json:"storeName"`
	Issuer                 string              `json:"issuer"`
	Status                 string              `json:"status"`
	LogURL                 string              `json:"logUrl"`
	Namespace              string              `json:"namespace"`
	CanonicalRef           string              `json:"canonicalRef"`
	AnchorString           string              `json:"anchorString"`
	JRD                    *mockObject         `json:"jrd"`
	Backoff                string              `json:"backoff"`
	Timeout                string              `json:"timeout"`
	LogMonitor             *mockObject         `json:"logMonitor"`
	LogMonitors            []*mockObject       `json:"logMonitors"`
	MaxTime                string              `json:"maxTime"`
	Index                  int                 `json:"index"`
	FromIndex              int                 `json:"fromIndex"`
	ToIndex                int                 `json:"toIndex"`
	Source                 string              `json:"source"`
	Age                    string              `json:"age"`
	MinAge                 string              `json:"minAge"`
	LogSpec                string              `json:"logSpec"`
}

func unmarshalLogData(t *testing.T, b []byte) *logData {
	t.Helper()

	l := &logData{}

	require.NoError(t, json.Unmarshal(b, l))

	return l
}

func parseURL(t *testing.T, raw string) *url.URL {
	t.Helper()

	u, err := url.Parse(raw)
	require.NoError(t, err)

	return u
}

type mockWriter struct {
	*bytes.Buffer
}

func (m *mockWriter) Sync() error {
	return nil
}

func newMockWriter() *mockWriter {
	return &mockWriter{Buffer: bytes.NewBuffer(nil)}
}
