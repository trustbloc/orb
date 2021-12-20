/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package ariesstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	ariesstorage "github.com/hyperledger/aries-framework-go/spi/storage"
	"github.com/trustbloc/edge-core/pkg/log"

	"github.com/trustbloc/orb/pkg/activitypub/store/memstore"
	"github.com/trustbloc/orb/pkg/activitypub/store/spi"
	"github.com/trustbloc/orb/pkg/activitypub/store/storeutil"
	"github.com/trustbloc/orb/pkg/activitypub/vocab"
	orberrors "github.com/trustbloc/orb/pkg/errors"
)

const (
	storeName           = "activitypub-ref"
	activityTag         = "Activity"
	objectIRITagName    = "ObjectIRI"
	refTypeTagName      = "RefType"
	timeAddedTagName    = "TimeAdded"
	activityTypeTagName = "ActivityType"
)

var logger = log.New("activitypub_store")

// Provider implements an ActivityPub store backed by an Aries storage provider.
type Provider struct {
	serviceName             string
	activityStore           ariesstorage.Store
	referenceStore          ariesstorage.Store
	actorStore              ariesstorage.Store
	multipleTagQueryCapable bool
}

// New returns a new ActivityPub storage provider.
// If multipleTagQueryCapable is set to true, then reference queries can be done using both the object IRI and activity
// type tags at the same time. NodeInfo uses this to optimize memory usage. Right now only the MongoDB provider
// supports this setting.
func New(serviceName string, provider ariesstorage.Provider, multipleTagQueryCapable bool) (*Provider, error) {
	stores, err := openStores(provider)
	if err != nil {
		return nil, fmt.Errorf("failed to open stores: %w", err)
	}

	return &Provider{
		serviceName:             serviceName,
		activityStore:           stores.activities,
		referenceStore:          stores.reference,
		actorStore:              stores.actor,
		multipleTagQueryCapable: multipleTagQueryCapable,
	}, nil
}

// PutActor stores the given actor.
func (s *Provider) PutActor(actor *vocab.ActorType) error {
	logger.Debugf("[%s] Storing actor [%s]", s.serviceName, actor.ID())

	actorBytes, err := json.Marshal(actor)
	if err != nil {
		return fmt.Errorf("failed to marshal actor: %w", err)
	}

	err = s.actorStore.Put(actor.ID().String(), actorBytes)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store actor: %w", err))
	}

	return nil
}

// GetActor returns the actor for the given IRI. Returns an ErrNoFound error if the actor is not in the store.
func (s *Provider) GetActor(iri *url.URL) (*vocab.ActorType, error) { //nolint: dupl // false positive
	logger.Debugf("[%s] Retrieving actor [%s]", s.serviceName, iri)

	actorBytes, err := s.actorStore.Get(iri.String())
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			return nil, spi.ErrNotFound
		}

		return nil,
			orberrors.NewTransient(fmt.Errorf("unexpected failure while getting actor from store: %w", err))
	}

	var actor vocab.ActorType

	err = json.Unmarshal(actorBytes, &actor)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal actor bytes: %w", err)
	}

	return &actor, nil
}

// AddActivity adds the given activity to the activity store.
func (s *Provider) AddActivity(activity *vocab.ActivityType) error {
	logger.Debugf("[%s] Storing activity - Type: %s, ID: %s",
		s.serviceName, activity.Type(), activity.ID())

	activityBytes, err := json.Marshal(activity)
	if err != nil {
		return fmt.Errorf("failed to marshal activity: %w", err)
	}

	err = s.activityStore.Put(activity.ID().String(), activityBytes,
		ariesstorage.Tag{
			Name: activityTag,
		}, ariesstorage.Tag{
			Name:  timeAddedTagName,
			Value: strconv.FormatInt(time.Now().UnixNano(), 10),
		})
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store activity: %w", err))
	}

	return nil
}

// GetActivity returns the activity for the given ID from the activity store
// or ErrNotFound error if it wasn't found.
func (s *Provider) GetActivity(activityID *url.URL) (*vocab.ActivityType, error) { //nolint: dupl // false positive
	logger.Debugf("[%s] Retrieving activity - ID: %s", s.serviceName, activityID)

	activityBytes, err := s.activityStore.Get(activityID.String())
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			return nil, spi.ErrNotFound
		}

		return nil,
			orberrors.NewTransient(fmt.Errorf("unexpected failure while getting activity from store: %w", err))
	}

	var activity vocab.ActivityType

	err = json.Unmarshal(activityBytes, &activity)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal activity bytes: %w", err)
	}

	return &activity, nil
}

// QueryActivities queries the given activity store using the provided criteria
// and returns a results iterator.
func (s *Provider) QueryActivities(query *spi.Criteria, opts ...spi.QueryOpt) (spi.ActivityIterator, error) {
	logger.Debugf("[%s] Querying activities - Query: %+v", s.serviceName, query)

	options := storeutil.GetQueryOptions(opts...)

	if query.ReferenceType != "" && query.ObjectIRI != nil {
		return s.queryActivitiesByRef(query.ReferenceType, query, opts...)
	}

	if len(query.ActivityIRIs) == 0 && len(query.Types) == 0 { // Get all activities
		iterator, err := s.activityStore.Query(activityTag,
			ariesstorage.WithSortOrder(&ariesstorage.SortOptions{
				Order:   ariesstorage.SortOrder(options.SortOrder),
				TagName: timeAddedTagName,
			}),
			ariesstorage.WithPageSize(options.PageSize),
			ariesstorage.WithInitialPageNum(options.PageNumber))
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to query store: %w", err))
		}

		return &activityIterator{ariesIterator: iterator}, nil
	}

	return nil, errors.New("unsupported query criteria")
}

// AddReference adds the reference of the given type to the given object.
func (s *Provider) AddReference(referenceType spi.ReferenceType, objectIRI *url.URL, referenceIRI *url.URL,
	refMetaDataOpts ...spi.RefMetadataOpt) error {
	logger.Debugf("[%s] Adding reference of type %s to object %s: %s",
		s.serviceName, referenceType, objectIRI, referenceIRI)

	valueBytes, err := json.Marshal(referenceIRI.String())
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	tags := determineTags(referenceType, objectIRI, refMetaDataOpts)

	err = s.referenceStore.Put(getRefKey(referenceType, objectIRI, referenceIRI), valueBytes, tags...)
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to store reference: %w", err))
	}

	return nil
}

// DeleteReference deletes the reference of the given type from the given object.
func (s *Provider) DeleteReference(referenceType spi.ReferenceType, objectIRI, referenceIRI *url.URL) error {
	logger.Debugf("[%s] Deleting reference of type %s from object %s: %s",
		s.serviceName, referenceType, objectIRI, referenceIRI)

	err := s.referenceStore.Delete(getRefKey(referenceType, objectIRI, referenceIRI))
	if err != nil {
		return orberrors.NewTransient(fmt.Errorf("failed to delete reference: %w", err))
	}

	return nil
}

// QueryReferences returns the list of references of the given type according to the given query.
func (s *Provider) QueryReferences(referenceType spi.ReferenceType, query *spi.Criteria,
	opts ...spi.QueryOpt) (spi.ReferenceIterator, error) {
	logger.Debugf("[%s] Querying references of type %s - Query: %+v", s.serviceName, referenceType, query)

	if query.ObjectIRI == nil {
		return nil, fmt.Errorf("object IRI is required")
	}

	options := storeutil.GetQueryOptions(opts...)

	// If no reference IRI is set, then grab all references associated with the object IRI.
	if query.ReferenceIRI == nil {
		queryExpression, err := s.generateQueryExpression(referenceType, query)
		if err != nil {
			return nil, err
		}

		iterator, errQuery := s.referenceStore.Query(
			queryExpression,
			ariesstorage.WithSortOrder(&ariesstorage.SortOptions{
				Order:   ariesstorage.SortOrder(options.SortOrder),
				TagName: timeAddedTagName,
			}),
			ariesstorage.WithPageSize(options.PageSize),
			ariesstorage.WithInitialPageNum(options.PageNumber),
		)
		if errQuery != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to query store: %w", errQuery))
		}

		return &referenceIterator{ariesIterator: iterator}, nil
	}

	// Otherwise, if there is a reference IRI,
	// then we should only grab the reference associated with the object IRI and reference IRI.
	retrievedURLBytes, err := s.referenceStore.Get(getRefKey(referenceType, query.ObjectIRI, query.ReferenceIRI))
	if err != nil {
		if errors.Is(err, ariesstorage.ErrDataNotFound) {
			return memstore.NewReferenceIterator(nil, 0), nil
		}

		return nil, orberrors.NewTransient(fmt.Errorf("unexpected failure while getting reference: %w", err))
	}

	var urlStr string

	err = json.Unmarshal(retrievedURLBytes, &urlStr)
	if err != nil {
		return nil, fmt.Errorf("unmarshal URL: %w", err)
	}

	retrievedURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL from storage: %w", err)
	}

	return memstore.NewReferenceIterator([]*url.URL{retrievedURL}, 1), nil
}

func (s *Provider) queryActivitiesByRef(refType spi.ReferenceType, query *spi.Criteria,
	opts ...spi.QueryOpt) (spi.ActivityIterator, error) {
	iterator, err := s.QueryReferences(refType, query, opts...)
	if err != nil {
		return nil, err
	}

	options := storeutil.GetQueryOptions(opts...)

	refs, err := storeutil.ReadReferences(iterator, options.PageSize)
	if err != nil {
		return nil, err
	}

	// The total item count from the activity iterator should reflect the total items from the original reference query,
	// regardless of page settings.
	totalItems, err := iterator.TotalItems()
	if err != nil {
		return nil,
			orberrors.NewTransient(fmt.Errorf("failed to get total items from reference iterator: %w", err))
	}

	if len(refs) == 0 {
		return memstore.NewActivityIterator(nil, totalItems), nil
	}

	activityIDs := make([]string, len(refs))

	for i, ref := range refs {
		activityIDs[i] = ref.String()
	}

	activitiesBytes, err := s.activityStore.GetBulk(activityIDs...)
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("unexpected failure while getting activities: %w", err))
	}

	var activities []*vocab.ActivityType

	for _, activityBytes := range activitiesBytes {
		if activityBytes != nil {
			var activity vocab.ActivityType

			err = json.Unmarshal(activityBytes, &activity)
			if err != nil {
				return nil, fmt.Errorf("failed to unmarshal activity bytes: %w", err)
			}

			activities = append(activities, &activity)
		}
	}

	return memstore.NewActivityIterator(activities, totalItems), nil
}

type activityIterator struct {
	ariesIterator ariesstorage.Iterator
}

func (a *activityIterator) TotalItems() (int, error) {
	return a.ariesIterator.TotalItems()
}

func (a *activityIterator) Next() (*vocab.ActivityType, error) {
	areMoreResults, err := a.ariesIterator.Next()
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to determine if there are more results: %w", err))
	}

	if areMoreResults {
		activityBytes, err := a.ariesIterator.Value()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to get value: %w", err))
		}

		var activity vocab.ActivityType

		err = json.Unmarshal(activityBytes, &activity)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal activity bytes: %w", err)
		}

		return &activity, nil
	}

	return nil, spi.ErrNotFound
}

func (a *activityIterator) Close() error {
	return a.ariesIterator.Close()
}

type referenceIterator struct {
	ariesIterator ariesstorage.Iterator
}

func (r *referenceIterator) TotalItems() (int, error) {
	return r.ariesIterator.TotalItems()
}

func (r *referenceIterator) Next() (*url.URL, error) {
	areMoreResults, err := r.ariesIterator.Next()
	if err != nil {
		return nil, orberrors.NewTransient(fmt.Errorf("failed to determine if there are more results: %w", err))
	}

	if areMoreResults {
		urlBytes, err := r.ariesIterator.Value()
		if err != nil {
			return nil, orberrors.NewTransient(fmt.Errorf("failed to get value: %w", err))
		}

		var urlStr string

		err = json.Unmarshal(urlBytes, &urlStr)
		if err != nil {
			return nil, fmt.Errorf("unmarshal URL: %w", err)
		}

		retrievedURL, err := url.Parse(urlStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse stored value as a URL: %w", err)
		}

		return retrievedURL, nil
	}

	return nil, spi.ErrNotFound
}

func (r *referenceIterator) Close() error {
	return r.ariesIterator.Close()
}

type stores struct {
	activities ariesstorage.Store
	reference  ariesstorage.Store
	actor      ariesstorage.Store
}

func openStores(provider ariesstorage.Provider) (stores, error) {
	activityStore, err := provider.OpenStore("activity")
	if err != nil {
		return stores{}, fmt.Errorf("failed to open activity store: %w", err)
	}

	err = provider.SetStoreConfig("activity",
		ariesstorage.StoreConfiguration{
			TagNames: []string{activityTag, timeAddedTagName},
		})
	if err != nil {
		return stores{}, fmt.Errorf("failed to set store configuration on activity store: %w", err)
	}

	referenceStore, err := openReferenceStore(provider)
	if err != nil {
		return stores{}, fmt.Errorf("failed to open reference stores: %w", err)
	}

	actorStore, err := provider.OpenStore("actor")
	if err != nil {
		return stores{}, fmt.Errorf("failed to open actor store: %w", err)
	}

	return stores{
		activities: activityStore,
		reference:  referenceStore,
		actor:      actorStore,
	}, nil
}

func openReferenceStore(provider ariesstorage.Provider) (ariesstorage.Store, error) {
	storeConfig := ariesstorage.StoreConfiguration{
		TagNames: []string{refTypeTagName, objectIRITagName, timeAddedTagName, activityTypeTagName},
	}

	store, err := provider.OpenStore(storeName)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s store: %w", storeName, err)
	}

	err = provider.SetStoreConfig(storeName, storeConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to set store configuration on %s store: %w",
			storeName, err)
	}

	return store, nil
}

func determineTags(referenceType spi.ReferenceType, objectIRI *url.URL,
	refMetaDataOpts []spi.RefMetadataOpt) []ariesstorage.Tag {
	refMetadata := storeutil.GetRefMetadata(refMetaDataOpts...)

	tags := []ariesstorage.Tag{
		{
			Name:  refTypeTagName,
			Value: string(referenceType),
		},
		{
			Name:  objectIRITagName,
			Value: base64.RawStdEncoding.EncodeToString([]byte(objectIRI.String())),
		},
		{
			Name:  timeAddedTagName,
			Value: strconv.FormatInt(time.Now().UnixNano(), 10),
		},
	}

	if refMetadata.ActivityType != "" {
		tags = append(tags, ariesstorage.Tag{Name: activityTypeTagName, Value: string(refMetadata.ActivityType)})
	}

	return tags
}

func (s *Provider) generateQueryExpression(referenceType spi.ReferenceType, query *spi.Criteria) (string, error) {
	if !s.multipleTagQueryCapable {
		return "", errors.New("cannot run query since the underlying storage provider does not support " +
			"querying with multiple tags")
	}

	queryExpression := fmt.Sprintf("%s:%s&&%s:%s", refTypeTagName, referenceType, objectIRITagName,
		base64.RawStdEncoding.EncodeToString([]byte(query.ObjectIRI.String())))

	if len(query.Types) > 0 {
		queryExpression += fmt.Sprintf("&&%s:%s", activityTypeTagName, query.Types[0])
	}

	return queryExpression, nil
}

func getRefKey(referenceType spi.ReferenceType, objectIRI, referenceIRI *url.URL) string {
	return fmt.Sprintf("%s-%s-%s", strings.ToLower(string(referenceType)), objectIRI, referenceIRI)
}
