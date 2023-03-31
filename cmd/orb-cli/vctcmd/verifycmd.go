/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package vctcmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hyperledger/aries-framework-go/component/storageutil/cachedstore"
	ariesmemstorage "github.com/hyperledger/aries-framework-go/component/storageutil/mem"
	"github.com/hyperledger/aries-framework-go/pkg/doc/ld"
	"github.com/hyperledger/aries-framework-go/pkg/doc/verifiable"
	ldstore "github.com/hyperledger/aries-framework-go/pkg/store/ld"
	jsonld "github.com/piprate/json-gold/ld"
	"github.com/spf13/cobra"
	"github.com/trustbloc/vct/pkg/client/vct"
	"github.com/trustbloc/vct/pkg/controller/command"

	"github.com/trustbloc/orb/cmd/orb-cli/common"
	"github.com/trustbloc/orb/internal/pkg/cmdutil"
	"github.com/trustbloc/orb/internal/pkg/ldcontext"
	"github.com/trustbloc/orb/pkg/anchor/util"
	"github.com/trustbloc/orb/pkg/linkset"
)

func newVerifyCmd(vctClientProvider vctClientProvider) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Updates the witness policy.",
		Long: `Verifies that a verifiable credential exists in the given VCT log. For example: vct verify ` +
			`--vc-hash 98752bbb-0140-47ca-85ab-e725807c9ae8 --url https://orb.domain1.com/vc ` +
			`--vct-url https://orb.vct/maple2022/v1`,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return executeVerify(cmd, vctClientProvider)
		},
	}

	addUpdateFlags(cmd)

	return cmd
}

func executeVerify(cmd *cobra.Command, vctClientProvider vctClientProvider) error {
	casURL, anchorHash, authToken, verbose, err := getVerifyArgs(cmd)
	if err != nil {
		return err
	}

	docLoader, err := newDocumentLoader()
	if err != nil {
		return fmt.Errorf("new document loader: %w", err)
	}

	vc, err := getVC(cmd, anchorHash, casURL, docLoader, verbose)
	if err != nil {
		return err
	}

	if verbose {
		common.Printf(cmd.OutOrStdout(), "Verifying %d proof(s) ...\n", len(vc.Proofs))
	}

	httpClient, err := common.NewHTTPClient(cmd)
	if err != nil {
		return fmt.Errorf("new HTTP client: %w", err)
	}

	vcBytes, err := json.Marshal(vc)
	if err != nil {
		return fmt.Errorf("marshal VC: %w", err)
	}

	var verifyResults []*verifyResult

	for _, proof := range vc.Proofs {
		result, e := verifyProof(cmd.OutOrStdout(), vcBytes, proof, httpClient, authToken,
			vctClientProvider, docLoader, verbose)
		if e != nil {
			common.Println(cmd.OutOrStdout(), e.Error())

			continue
		}

		verifyResults = append(verifyResults, result)
	}

	resultBytes, err := json.MarshalIndent(verifyResults, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal verify results: %w", err)
	}

	common.Println(cmd.OutOrStdout(), string(resultBytes))

	return nil
}

type vctClient interface {
	GetSTH(ctx context.Context) (*command.GetSTHResponse, error)
	GetProofByHash(ctx context.Context, hash string, treeSize uint64) (*command.GetProofByHashResponse, error)
}

type vctClientProvider interface {
	GetVCTClient(domain string, opts ...vct.ClientOpt) vctClient
}

func verifyProof(out io.Writer, vcBytes []byte, proof verifiable.Proof, httpClient *http.Client,
	authToken string, vctClientProvider vctClientProvider, docLoader jsonld.DocumentLoader, verbose bool,
) (*verifyResult, error) {
	domain, createdTime, err := getVCParameters(proof)
	if err != nil {
		return nil, err
	}

	result := &verifyResult{
		Domain: domain,
	}

	// calculates leaf hash for given timestamp and initial credential to be able to query proof by hash.
	leafHash, err := vct.CalculateLeafHash(uint64(createdTime.UnixNano()/int64(time.Millisecond)), vcBytes, docLoader)
	if err != nil {
		result.Error = fmt.Errorf("calculate leaf hash: %w", err).Error()

		return result, nil
	}

	// TODO: Auth read token should be per domain.
	client := vctClientProvider.GetVCTClient(domain,
		vct.WithHTTPClient(httpClient),
		vct.WithAuthReadToken(authToken),
	)

	// Get the latest signed tree head to get the tree size.
	sth, err := client.GetSTH(context.Background())
	if err != nil {
		result.Error = err.Error()

		return result, nil //nolint:nilerr
	}

	if verbose {
		common.Printf(out, "... retrieved STH from %s - Tree size: %d\n\n", domain, sth.TreeSize)
	}

	resp, err := client.GetProofByHash(context.Background(), leafHash, sth.TreeSize)
	if err != nil {
		if strings.Contains(err.Error(), "no proof") {
			if verbose {
				common.Printf(out, "... proof was NOT found in VCT log %s\n", domain)
			}
		} else {
			result.Error = err.Error()
		}

		return result, nil
	}

	if verbose {
		common.Printf(out, "... proof was found in VCT log %s at leaf index: %d\n", domain, resp.LeafIndex)
	}

	result.Found = true
	result.Index = resp.LeafIndex
	result.AuditPath = resp.AuditPath

	return result, nil
}

func addUpdateFlags(cmd *cobra.Command) {
	common.AddCommonFlags(cmd)

	cmd.Flags().StringP(casURLFlagName, "", "", casURLFlagUsage)
	cmd.Flags().StringP(anchorHashFlagName, "", "", anchorHashFlagUsage)
	cmd.Flags().StringP(verboseFlagName, "", "false", verboseFlagUsage)
	cmd.Flags().StringP(vctAuthTokenFlagName, "", "false", vctAuthTokenFlagUsage)
}

func getVerifyArgs(cmd *cobra.Command) (casURL, anchorHash, authToken string, verbose bool, err error) {
	casURL, err = cmdutil.GetUserSetVarFromString(cmd, casURLFlagName, casURLEnvKey, false)
	if err != nil {
		return "", "", "", false, err
	}

	_, err = url.Parse(casURL)
	if err != nil {
		return "", "", "", false, fmt.Errorf("invalid CAS URL %s: %w", casURL, err)
	}

	anchorHash, err = cmdutil.GetUserSetVarFromString(cmd, anchorHashFlagName, anchorHashEnvKey, false)
	if err != nil {
		return "", "", "", false, err
	}

	authToken = cmdutil.GetUserSetOptionalVarFromString(cmd, vctAuthTokenFlagName, vctAuthTokenEnvKey)

	verboseStr := cmdutil.GetUserSetOptionalVarFromString(cmd, verboseFlagName, verboseEnvKey)
	if verboseStr != "" {
		verbose = true
	}

	return casURL, anchorHash, authToken, verbose, nil
}

func getVC(cmd *cobra.Command, anchorHash, casURL string, docLoader jsonld.DocumentLoader,
	verbose bool,
) (*verifiable.Credential, error) {
	anchorLinksetBytes, err := common.SendHTTPRequest(cmd, nil, http.MethodGet,
		fmt.Sprintf("%s/%s", casURL, anchorHash))
	if err != nil {
		return nil, fmt.Errorf("get anchor linkset from %s: %w", casURL, err)
	}

	if verbose {
		common.Printf(cmd.OutOrStdout(), "Anchor linkset:\n%s\n\n", anchorLinksetBytes)
	}

	anchorLinkset := &linkset.Linkset{}

	err = json.Unmarshal(anchorLinksetBytes, anchorLinkset)
	if err != nil {
		return nil, fmt.Errorf("unmarshal anchor linkset: %w", err)
	}

	vc, err := util.VerifiableCredentialFromAnchorLink(anchorLinkset.Link(),
		verifiable.WithDisabledProofCheck(),
		verifiable.WithJSONLDDocumentLoader(docLoader),
	)
	if err != nil {
		return nil, fmt.Errorf("get verifiable credential from anchor link: %w", err)
	}

	if verbose {
		vcBytes, err := json.MarshalIndent(vc, "", "  ")
		if err != nil {
			common.Printf(cmd.OutOrStdout(), "Verifiable credential: %s", err)
		} else {
			common.Printf(cmd.OutOrStdout(), "Verifiable credential:\n%s\n\n", vcBytes)
		}
	}

	return vc, nil
}

func newDocumentLoader() (jsonld.DocumentLoader, error) {
	ldStorageProvider := cachedstore.NewProvider(ariesmemstorage.NewProvider(), ariesmemstorage.NewProvider())

	contextStore, err := ldstore.NewContextStore(ldStorageProvider)
	if err != nil {
		return nil, fmt.Errorf("create JSON-LD context store: %w", err)
	}

	remoteProviderStore, err := ldstore.NewRemoteProviderStore(ldStorageProvider)
	if err != nil {
		return nil, fmt.Errorf("create remote provider store: %w", err)
	}

	ldStore := &ldStoreProvider{
		ContextStore:        contextStore,
		RemoteProviderStore: remoteProviderStore,
	}

	docLoader, err := createJSONLDDocumentLoader(ldStore)
	if err != nil {
		return nil, fmt.Errorf("failed to load Orb contexts: %w", err)
	}

	return docLoader, nil
}

func createJSONLDDocumentLoader(ldStore *ldStoreProvider) (jsonld.DocumentLoader, error) {
	loaderOpts := []ld.DocumentLoaderOpts{ld.WithExtraContexts(ldcontext.MustGetAll()...)}

	loader, err := ld.NewDocumentLoader(ldStore, loaderOpts...)
	if err != nil {
		return nil, fmt.Errorf("new document loader: %w", err)
	}

	return loader, nil
}

func getVCParameters(proof verifiable.Proof) (domain string, created time.Time, err error) {
	d, ok := proof["domain"]
	if !ok {
		return "", time.Time{}, errors.New("'domain' not found in VC")
	}

	c, ok := proof["created"]
	if !ok {
		return "", time.Time{}, errors.New("'created' not found in VC")
	}

	createdTime, err := time.Parse(time.RFC3339, c.(string))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("parse 'created': %w", err)
	}

	return d.(string), createdTime, nil //nolint:forcetypeassert
}

type ldStoreProvider struct {
	ContextStore        ldstore.ContextStore
	RemoteProviderStore ldstore.RemoteProviderStore
}

func (p *ldStoreProvider) JSONLDContextStore() ldstore.ContextStore {
	return p.ContextStore
}

func (p *ldStoreProvider) JSONLDRemoteProviderStore() ldstore.RemoteProviderStore {
	return p.RemoteProviderStore
}

type verifyResult struct {
	Domain    string   `json:"domain"`
	Found     bool     `json:"found"`
	Index     int64    `json:"leafIndex"`
	AuditPath [][]byte `json:"auditPath"`
	Error     string   `json:"error,omitempty"`
}

type clientProvider struct{}

func (p *clientProvider) GetVCTClient(domain string, opts ...vct.ClientOpt) vctClient {
	return vct.New(domain, opts...)
}
