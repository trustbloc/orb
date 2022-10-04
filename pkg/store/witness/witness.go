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

	"github.com/trustbloc/orb/internal/pkg/log"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	"github.com/trustbloc/orb/pkg/anchor/witness/proof"
	orberrors "github.com/trustbloc/orb/pkg/errors"
	"github.com/trustbloc/orb/pkg/store"
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

var logger = log.NewStructured("witness-store")

// New creates new anchor witness store.
func New(provider storage.Provider, expiryService *expiry.Service, expiryPeriod time.Duration) (*Store, error) {
	s, err := store.Open(provider, namespace,
		store.NewTagGroup(anchorIndexTagName, typeTagName),
		store.NewTagGroup(expiryTagName),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open anchor witness store: %w", err)
	}

	ws := &Store{
		store:        s,
		expiryPeriod: expiryPeriod,
	}

	expiryService.Register(s, expiryTagName, namespace, expiry.WithExpiryHandler(ws))

	return ws, nil
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
		value, err := json.Marshal(s.newWitnessInfo(anchorIDEncoded, w))
		if err != nil {
			return fmt.Errorf("failed to marshal anchor witness: %w", err)
		}

		logger.Debug("Adding witness to storage batch", log.WithType(string(w.Type)), log.WithURI(w.URI))

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

	logger.Debug("Stored witnesses for anchor", log.WithTotal(len(witnesses)), log.WithAnchorURIString(anchorID))

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
			log.CloseIteratorError(logger, err)
		}
	}()

	ok, err := iter.Next()
	if err != nil {
		return orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, err)
	}

	if !ok {
		logger.Debug("No witnesses to delete for anchor - nothing to do.", log.WithAnchorURIString(anchorID))

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

	logger.Debug("Deleted witnesses for anchor.", log.WithTotal(len(witnessKeys)), log.WithAnchorURIString(anchorID))

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

	query := fmt.Sprintf(queryExpr, anchorIndexTagName, anchorIDEncoded, typeTagName, witnessInfoType)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransientf("failed to query witnesses for anchorID[%s]: %w", query, err)
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			log.CloseIteratorError(logger, err)
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

		witnessInfo := &witnessInfo{}

		e = json.Unmarshal(value, witnessInfo)
		if e != nil {
			return nil, fmt.Errorf("failed to unmarshal anchor witness from store value for anchorID[%s]: %w",
				anchorID, e)
		}

		witnesses = append(witnesses, witnessInfo.Witness)

		ok, e = iter.Next()
		if e != nil {
			return nil, orberrors.NewTransientf(iteratorErrMsgFormat, anchorID, e)
		}
	}

	logger.Debug("Retrieved witnesses for anchor", log.WithTotal(len(witnesses)), log.WithAnchorURIString(anchorID))

	if len(witnesses) == 0 {
		return nil, fmt.Errorf("anchorID[%s] not found in the store", anchorID)
	}

	return witnesses, nil
}

func (s *Store) getProofs(anchorID string) (proofs, error) {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf(queryExpr, anchorIndexTagName, anchorIDEncoded, typeTagName, proofType)

	iter, err := s.store.Query(query)
	if err != nil {
		return nil, orberrors.NewTransientf("failed to get proofs for[%s]: %w", query, err)
	}

	defer func() {
		err = iter.Close()
		if err != nil {
			log.CloseIteratorError(logger, err)
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

	logger.Debug("Retrieved witness proofs for anchor", log.WithTotal(len(proofs)), log.WithAnchorURIString(anchorID))

	return proofs, nil
}

// AddProof adds proof for anchor id and witness.
func (s *Store) AddProof(anchorID string, witness *url.URL, p []byte) error {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	wp := s.newWitnessProof(anchorIDEncoded, witness, p)

	wpBytes, err := json.Marshal(wp)
	if err != nil {
		return fmt.Errorf("marshal proof for anchorID[%s], witness[%s]: %w", anchorID, witness, err)
	}

	err = s.store.Put(uuid.New().String(), wpBytes,
		storage.Tag{Name: typeTagName, Value: wp.EntryType},
		storage.Tag{Name: anchorIndexTagName, Value: wp.AnchorID},
		storage.Tag{Name: expiryTagName, Value: fmt.Sprintf("%d", wp.ExpiryTime)},
	)
	if err != nil {
		return orberrors.NewTransientf("store proof for anchorID[%s], witness[%s]: %w", anchorID, witness, err)
	}

	logger.Debug("Successfully stored proof for anchor from witness",
		log.WithAnchorURIString(anchorID), log.WithWitnessURI(witness), log.WithProof(p))

	return nil
}

// UpdateWitnessSelection updates witness selection flag.
func (s *Store) UpdateWitnessSelection(anchorID string, witnesses []*url.URL, selected bool) error {
	anchorIDEncoded := base64.RawURLEncoding.EncodeToString([]byte(anchorID))

	query := fmt.Sprintf(queryExpr, anchorIndexTagName, anchorIDEncoded, typeTagName, witnessInfoType)

	iter, err := s.store.Query(query)
	if err != nil {
		return orberrors.NewTransientf("failed to query witnesses to update for anchorID[%s]: %w", query, err)
	}

	defer func() {
		if e := iter.Close(); e != nil {
			log.CloseIteratorError(logger, err)
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

			logger.Debug("Updated witness proof for anchor/witness", log.WithAnchorURIString(anchorID),
				log.WithWitnessURI(w.URI))
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

	w := &witnessInfo{}

	err = json.Unmarshal(value, w)
	if err != nil {
		return "", nil, fmt.Errorf("unmarshal anchor witness from store value: %w", err)
	}

	key, err := iter.Key()
	if err != nil {
		return "", nil, orberrors.NewTransientf("get key: %w", err)
	}

	return key, w.Witness, nil
}

func (s *Store) storeWitness(key string, w *proof.Witness, anchorIDEncoded string) error {
	info := s.newWitnessInfo(anchorIDEncoded, w)

	witnessBytes, marshalErr := json.Marshal(info)
	if marshalErr != nil {
		return fmt.Errorf("marshal witness[%s]: %w", w.URI, marshalErr)
	}

	err := s.store.Put(key, witnessBytes,
		storage.Tag{Name: typeTagName, Value: info.EntryType},
		storage.Tag{Name: anchorIndexTagName, Value: info.AnchorID},
		storage.Tag{Name: expiryTagName, Value: fmt.Sprintf("%d", info.ExpiryTime)},
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
		entryBytes, err := s.store.Get(key)
		if err != nil {
			logger.Error("Error getting tags for expired key", log.WithKeyID(key), log.WithError(err))

			return nil
		}

		entry := &Entry{}

		err = json.Unmarshal(entryBytes, entry)
		if err != nil {
			logger.Error("Failed to unmarshal expired entry for key", log.WithKey(key), log.WithError(err))

			continue
		}

		anchor, err := base64.RawURLEncoding.DecodeString(entry.AnchorID)
		if err != nil {
			logger.Error("Failed to decode encoded anchor", log.WithAnchorURIString(entry.AnchorID), log.WithError(err))

			return nil
		}

		uniqueAnchors[string(anchor)] = true
	}

	anchors := make([]string, 0, len(uniqueAnchors))
	for a := range uniqueAnchors {
		anchors = append(anchors, a)
	}

	logger.Error("Failed to process anchors", log.WithAnchorURIStrings(anchors...))

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

// Entry contains common data for for witness-info and witness-proof.
type Entry struct {
	EntryType  string `json:"entryType"`
	AnchorID   string `json:"anchorID"`
	ExpiryTime int64  `json:"expiryTime"`
}

type witnessInfo struct {
	*Entry
	*proof.Witness
}

type witnessProof struct {
	*Entry
	WitnessURI *vocab.URLProperty `json:"witness"`
	Proof      []byte             `json:"proof"`
}

func (s *Store) newWitnessInfo(anchorID string, w *proof.Witness) *witnessInfo {
	return &witnessInfo{
		Entry: &Entry{
			EntryType:  witnessInfoType,
			AnchorID:   anchorID,
			ExpiryTime: time.Now().Add(s.expiryPeriod).Unix(),
		},
		Witness: w,
	}
}

func (s *Store) newWitnessProof(anchorID string, uri *url.URL, prf []byte) *witnessProof {
	return &witnessProof{
		Entry: &Entry{
			EntryType:  proofType,
			AnchorID:   anchorID,
			ExpiryTime: time.Now().Add(s.expiryPeriod).Unix(),
		},
		WitnessURI: vocab.NewURLProperty(uri),
		Proof:      prf,
	}
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

		if proofs != nil {
			if wp := proofs.get(w.URI.URL()); wp != nil {
				p.Proof = wp.Proof
			}
		}

		witnessProofs = append(witnessProofs, p)
	}

	return witnessProofs
}
