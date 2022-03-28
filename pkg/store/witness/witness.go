/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package witness

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"
	"github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store/expiry"
)

const (
	namespace = "witness"

	typeTagName     = "entryType"
	witnessInfoType = "witness-info"
	proofType       = "witness-proof"

	anchorIndexTagName = "anchorID"
	expiryTagName      = "ExpiryTime"

	queryExpr = "%s:%s&&%s:%s"

	iteratorErrMsgFormat = "iterator error for anchorID[%s] : %w"
)

var logger = log.New("witness-store")

// New creates new anchor witness store.
func New(provider storage.Provider, expiryService *expiry.Service, expiryPeriod time.Duration) (*Store, error) {
	store, err := provider.OpenStore(namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to open anchor witness store: %w", err)
	}

	s := &Store{
		store:        store,
		expiryPeriod: expiryPeriod,
	}

	err = provider.SetStoreConfig(namespace,
		storage.StoreConfiguration{
			TagNames: []string{typeTagName, anchorIndexTagName, expiryTagName},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration: %w", err)
	}

	expiryService.Register(store, expiryTagName, namespace, expiry.WithExpiryHandler(s))

	return s, nil
}

// Store is db implementation of anchor witness store.
type Store struct {
	store        storage.Store
	expiryPeriod time.Duration
}

// Put saves witnesses into anchor witness store.
func (s *Store) Put(anchorID string, witnesses []*proof.Witness) error {
	operations := make([]storage.Operation, len(witnesses))

	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	putOptions := &storage.PutOptions{IsNewKey: true}

	for i, w := range witnesses {
		value, err := json.Marshal(w)
		if err != nil {
			return fmt.Errorf("failed to marshal anchor witness: %w", err)
		}

		logger.Debugf("adding %s witness to storage batch: %s", w.Type, w.URI)

		op := storage.Operation{
			Key:   uuid.New().String(),
			Value: value,
			Tags: []storage.Tag{
				{Name: typeTagName, Value: witnessInfoType},
				{Name: anchorIndexTagName, Value: anchorIDEncoded},
				{Name: expiryTagName, Value: fmt.Sprintf("%d", time.Now().Add(s.expiryPeriod).Unix())},
			},
			PutOptions: putOptions,
		}

		operations[i] = op
	}

	err := s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransientf("failed to store witnesses for anchorID[%s]: %w", anchorID, err)
	}

	logger.Debugf("stored %d witnesses for anchorID[%s]", len(witnesses), anchorID)

	return nil
}

// Delete deletes all witnesses associated with anchor ID.
func (s *Store) Delete(anchorID string) error {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))
	query := fmt.Sprintf("%s:%s", anchorIndexTagName, anchorIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return orberrors.NewTransientf("failed to query witnesses to delete for anchorID[%s]: %w", query, err)
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	ok, err := iter.Next()
	if err != nil {
		return orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, err)
	}

	if !ok {
		logger.Debugf("no witnesses to delete for anchorID[%s], nothing to do", anchorID)

		return nil
	}

	var witnessKeys []string

	for ok {
		var key string

		key, err = iter.Key()
		if err != nil {
			return orberrors.NewTransientf("failed to get witness to delete from iterator value for anchorID[%s]: %w",
				anchorID, err)
		}

		witnessKeys = append(witnessKeys, key)

		ok, err = iter.Next()
		if err != nil {
			return orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, err)
		}
	}

	operations := make([]storage.Operation, len(witnessKeys))

	for i, k := range witnessKeys {
		operations[i] = storage.Operation{Key: k}
	}

	err = s.store.Batch(operations)
	if err != nil {
		return orberrors.NewTransientf("failed to delete witnesses for anchorID[%s]: %w", anchorID, err)
	}

	logger.Debugf("deleted %d witnesses for anchorID[%s]", len(witnessKeys), anchorID)

	return nil
}

// Get retrieves witnesses for the given anchor id.
func (s *Store) Get(anchorID string) ([]*proof.WitnessProof, error) {
	witnesses, err := s.getWitnesses(anchorID)
	if err != nil {
		return nil, fmt.Errorf("get witnesses for anchor [%s]: %w", anchorID, err)
	}

	proofs, err := s.getProofs(anchorID)
	if err != nil {
		return nil, fmt.Errorf("get witness proofs for anchor [%s]: %w", anchorID, err)
	}

	return getWitnessProofs(witnesses, proofs), nil
}

func (s *Store) getWitnesses(anchorID string) ([]*proof.Witness, error) {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf(queryExpr, typeTagName, witnessInfoType, anchorIndexTagName, anchorIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransientf("failed to query witnesses for anchorID[%s]: %w", query, err)
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	ok, err := iter.Next()
	if err != nil {
		return nil, orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, err)
	}

	var witnesses []*proof.Witness

	for ok {
		value, e := iter.Value()
		if e != nil {
			return nil, orberrors.NewTransientf("failed to get witness from iterator value for anchorID[%s]: %w",
				anchorID, e)
		}

		var witness proof.Witness

		e = json.Unmarshal(value, &witness)
		if e != nil {
			return nil, fmt.Errorf("failed to unmarshal anchor witness from store value for anchorID[%s]: %w",
				anchorID, e)
		}

		witnesses = append(witnesses, &witness)

		ok, e = iter.Next()
		if e != nil {
			return nil, orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, e)
		}
	}

	logger.Debugf("retrieved %d witnesses for anchorID[%s]", len(witnesses), anchorID)

	if len(witnesses) == 0 {
		return nil, fmt.Errorf("anchorID[%s] not found in the store", anchorID)
	}

	return witnesses, nil
}

func (s *Store) getProofs(anchorID string) (proofs, error) {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf(queryExpr, typeTagName, proofType, anchorIndexTagName, anchorIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransientf("failed to get proofs for[%s]: %w", query, err)
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	ok, err := iter.Next()
	if err != nil {
		return nil, orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, err)
	}

	var proofs []*witnessProof

	for ok {
		value, e := iter.Value()
		if e != nil {
			return nil, orberrors.NewTransientf("failed to get witness proof from iterator for anchorID[%s]: %w",
				anchorID, e)
		}

		p := &witnessProof{}

		e = json.Unmarshal(value, p)
		if e != nil {
			return nil, fmt.Errorf("unmarshal witness proof for anchorID[%s]: %w", anchorID, e)
		}

		proofs = append(proofs, p)

		ok, e = iter.Next()
		if e != nil {
			return nil, orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, err)
		}
	}

	logger.Debugf("retrieved %d witness proofs for anchorID[%s]", len(proofs), anchorID)

	return proofs, nil
}

// AddProof adds proof for anchor id and witness.
func (s *Store) AddProof(anchorID string, witness *url.URL, p []byte) error {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	wp := &witnessProof{
		WitnessURI: vocab.NewURLProperty(witness),
		Proof:      p,
	}

	wpBytes, err := json.Marshal(wp)
	if err != nil {
		return fmt.Errorf("marshal proof for anchorID[%s], witness[%s]: %w", anchorID, witness, err)
	}

	err = s.store.Put(uuid.New().String(), wpBytes,
		storage.Tag{Name: typeTagName, Value: proofType},
		storage.Tag{Name: anchorIndexTagName, Value: anchorIDEncoded},
		storage.Tag{Name: expiryTagName, Value: fmt.Sprintf("%d", time.Now().Add(s.expiryPeriod).Unix())},
	)
	if err != nil {
		return orberrors.NewTransientf("store proof for anchorID[%s], witness[%s]: %w", anchorID, witness, err)
	}

	logger.Debugf("Successfully stored proof for anchorID[%s] from witness [%s]: %s", anchorID, witness, p)

	return nil
}

// UpdateWitnessSelection updates witness selection flag.
func (s *Store) UpdateWitnessSelection(anchorID string, witnesses []*url.URL, selected bool) error {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf(queryExpr, typeTagName, witnessInfoType, anchorIndexTagName, anchorIDEncoded)

	iter, err := s.store.Query(query)
	if err != nil {
		return orberrors.NewTransientf("failed to query witnesses to update for anchorID[%s]: %w", query, err)
	}

	defer func() {
		if e := iter.Close(); e != nil {
			logger.Errorf("failed to close iterator: %s", err.Error())
		}
	}()

	ok, err := iter.Next()
	if err != nil {
		return orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, err)
	}

	updatedNo := 0

	witnessesMap := getWitnessesMap(witnesses)

	for ok {
		key, w, e := getWitness(iter)
		if e != nil {
			return fmt.Errorf("get next witness from iterator for anchorID[%s]: %w", anchorID, e)
		}

		if _, ok = witnessesMap[w.URI.String()]; ok {
			w.Selected = selected

			e = s.storeWitness(key, w, anchorIDEncoded)
			if e != nil {
				return fmt.Errorf("store witness for anchorID[%s]: %w", anchorID, e)
			}

			updatedNo++

			logger.Debugf("updated witness proof for anchorID[%s] and witness[%s]", anchorID, w.URI.String())
		}

		ok, e = iter.Next()
		if e != nil {
			return orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, e)
		}
	}

	if updatedNo == 0 {
		return fmt.Errorf("witness%s not found for anchorID[%s]", witnesses, anchorID)
	}

	return nil
}

func getWitness(iter storage.Iterator) (string, *proof.Witness, error) {
	value, err := iter.Value()
	if err != nil {
		return "", nil, orberrors.NewTransientf("get iterator value: %w", err)
	}

	w := &proof.Witness{}

	err = json.Unmarshal(value, w)
	if err != nil {
		return "", nil, fmt.Errorf("unmarshal anchor witness from store value: %w", err)
	}

	key, err := iter.Key()
	if err != nil {
		return "", nil, orberrors.NewTransientf("get key: %w", err)
	}

	return key, w, nil
}

func (s *Store) storeWitness(key string, w *proof.Witness, anchorIDEncoded string) error {
	witnessBytes, marshalErr := json.Marshal(w)
	if marshalErr != nil {
		return fmt.Errorf("marshal witness[%s]: %w", w.URI, marshalErr)
	}

	err := s.store.Put(key, witnessBytes,
		storage.Tag{Name: typeTagName, Value: witnessInfoType},
		storage.Tag{Name: anchorIndexTagName, Value: anchorIDEncoded},
		storage.Tag{Name: expiryTagName, Value: fmt.Sprintf("%d", time.Now().Add(s.expiryPeriod).Unix())},
	)
	if err != nil {
		return orberrors.NewTransientf("store witness[%s]: %w", w.URI, err)
	}

	return nil
}

// HandleExpiredKeys is expired keys inspector/handler.
func (s *Store) HandleExpiredKeys(keys ...string) error {
	if len(keys) == 0 {
		return nil
	}

	uniqueAnchors := make(map[string]bool)

	for _, key := range keys {
		tags, err := s.store.GetTags(key)
		if err != nil {
			logger.Errorf("get tags for expired key[%s]: %s", key, err)

			return nil
		}

		for _, tag := range tags {
			if tag.Name == anchorIndexTagName {
				anchor, err := base64.RawURLEncoding.DecodeString(tag.Value)
				if err != nil {
					logger.Errorf("failed to decode encoded anchor[%s]: %s", tag.Value, err)

					return nil
				}

				uniqueAnchors[string(anchor)] = true
			}
		}
	}

	anchors := make([]string, 0, len(uniqueAnchors))
	for a := range uniqueAnchors {
		anchors = append(anchors, a)
	}

	logger.Errorf("failed to process anchors: %s", anchors)

	return nil
}

func getWitnessesMap(witnesses []*url.URL) map[string]bool {
	witnessesMap := make(map[string]bool)

	for _, w := range witnesses {
		_, ok := witnessesMap[w.String()]
		if !ok {
			witnessesMap[w.String()] = true
		}
	}

	return witnessesMap
}

type witnessProof struct {
	WitnessURI *vocab.URLProperty `json:"witness"`
	Proof      []byte             `json:"proof"`
}

type proofs []*witnessProof

func (p proofs) get(witness *url.URL) *witnessProof {
	for _, wp := range p {
		if wp.WitnessURI == nil || witness == nil {
			continue
		}

		if wp.WitnessURI.String() == witness.String() {
			return wp
		}
	}

	return nil
}

func getWitnessProofs(witnesses []*proof.Witness, proofs proofs) []*proof.WitnessProof {
	var witnessProofs []*proof.WitnessProof

	for _, w := range witnesses {
		p := &proof.WitnessProof{
			Witness: w,
		}

		wp := proofs.get(w.URI.URL())
		if wp != nil {
			p.Proof = wp.Proof
		}

		witnessProofs = append(witnessProofs, p)
	}

	return witnessProofs
}
