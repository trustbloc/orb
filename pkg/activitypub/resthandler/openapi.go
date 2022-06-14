/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package resthandler

import "github.com/trustbloc/orb/pkg/activitypub/vocab"

// Request message
//
// swagger:parameters acceptListGetReq
type acceptListGetReq struct { // nolint: unused,deadcode
	// Type
	// enum: follow,invite-witness
	Type string `json:"type"`
}

// Response message
//
// swagger:response acceptListGetResp
type acceptListGetResp struct { // nolint: unused,deadcode
	// in: body
	Body []acceptList
}

//nolint:lll
// handleGet swagger:route GET /acceptlist ActivityPub acceptListGetReq
//
// Returns the accept-list. If type is specified then the accept-list for the given type (follow or invite-witness) is returned, otherwise all accept-lists are returned.
//
// Responses:
//        200: acceptListGetResp
func acceptlistGetRequest() { // nolint: unused,deadcode
}

// Request message
//
// swagger:parameters acceptListPostReq
type acceptListPostReq struct { // nolint: unused,deadcode
	// in: body
	Body []acceptListRequest
}

// Response message
//
// swagger:response acceptListPostResp
type acceptListPostResp struct { // nolint: unused,deadcode
	Body string
}

// handlePost swagger:route POST /acceptlist ActivityPub acceptListPostReq
//
// Updates the accept-list.
//
// Responses:
//    200: acceptListPostResp
func acceptlistPostRequest() { // nolint: unused,deadcode
}

// swagger:parameters serviceGetReq
type serviceGetReq struct { // nolint: unused,deadcode
}

// swagger:response serviceGetResp
type serviceGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.ActorType
}

//nolint:lll
// serviceGetRequest swagger:route GET /services/orb ActivityPub serviceGetReq
//
// The Orb service is retrieved using the /services/orb endpoint. The returned data is a JSON document that contains REST endpoints that may be queried to return additional information.
//
// Produces:
// - application/json
//
// Responses:
//        200: serviceGetResp
func serviceGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters serviceKeysGetReq
type serviceKeysGetReq struct { // nolint: unused,deadcode
	// In: path
	ID string `json:"id"`
}

// swagger:response serviceKeysGetResp
type serviceKeysGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.PublicKeyType
}

// serviceKeysGetRequest swagger:route GET /services/orb/keys/{id} ActivityPub serviceKeysGetReq
//
// The public key of an Orb service is retrieved using this endpoint.
//
// Produces:
// - application/json
//
// Responses:
//        200: serviceKeysGetResp
func serviceKeysGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters followersGetReq
type followersGetReq struct { // nolint: unused,deadcode
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response followersGetResp
type followersGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// followersGetRequest swagger:route GET /services/orb/followers ActivityPub followersGetReq
//
// The followers of this Orb service are returned via this endpoint. If no paging parameters are specified in the URL then the response contains information about the collection, i.e. the links to the first and last page, as well as the total number of items in the collection. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: followersGetResp
func followersGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters followingGetReq
type followingGetReq struct { // nolint: unused,deadcode
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response followingGetResp
type followingGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// followingGetRequest swagger:route GET /services/orb/following ActivityPub followingGetReq
//
// The services following this Orb service are returned via this endpoint. If no paging parameters are specified in the URL then the response contains information about the collection, i.e. the links to the first and last page, as well as the total number of items in the collection. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: followingGetResp
func followingGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters witnessesGetReq
type witnessesGetReq struct { // nolint: unused,deadcode
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response witnessesGetResp
type witnessesGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// witnessesGetRequest swagger:route GET /services/orb/witnesses ActivityPub witnessesGetReq
//
// The witnesses of this service are returned via this endpoint. If no paging parameters are specified in the URL then the response contains information about the witnesses collection, i.e. the links to the first and last page, as well as the total number of items in the collection. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: witnessesGetResp
func witnessesGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters witnessingGetReq
type witnessingGetReq struct { // nolint: unused,deadcode
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response witnessingGetResp
type witnessingGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// witnessingGetRequest swagger:route GET /services/orb/witnessing ActivityPub witnessingGetReq
//
// The services that are witnessing anchor events for this service are returned via this endpoint. If no paging parameters are specified in the URL then the response contains information about the collection, i.e. the links to the first and last page, as well as the total number of items in the collection. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: witnessingGetResp
func witnessingGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters inboxGetReq
type inboxGetReq struct { // nolint: unused,deadcode
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response inboxGetResp
type inboxGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// inboxGetRequest swagger:route GET /services/orb/inbox ActivityPub inboxGetReq
//
// The activities posted to the inbox of this service are returned via this endpoint. If no paging parameters are specified in the URL then the response contains information about the inbox collection, i.e. the links to the first and last page, as well as the total number of items in the inbox. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: inboxGetResp
func inboxGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters inboxPostReq
type inboxPostReq struct { // nolint: unused,deadcode
	// in: body
	Body vocab.ActivityType
}

// swagger:response inboxPostResp
type inboxPostResp struct { // nolint: unused,deadcode
	// in: body
	Body string
}

//nolint:lll
// inboxPostRequest swagger:route POST /services/orb/inbox ActivityPub inboxPostReq
//
// A POST request to the inbox endpoint adds the activity contained in the request to the service’s Inbox, which will be processed by the ActivityPub Inbox. This endpoint is restricted by authorization rules, i.e. the requester must sign the HTTP request. Some activities also have authorization rules such that the actor must be in the destination server’s followers and/or witnessing collection.
//
// Consumes:
// - application/json
//
// Responses:
//        200: inboxPostResp
func inboxPostRequest() { // nolint: unused,deadcode
}

// swagger:parameters outboxGetReq
type outboxGetReq struct { // nolint: unused,deadcode
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response outboxGetResp
type outboxGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// outboxGetRequest swagger:route GET /services/orb/outbox ActivityPub outboxGetReq
//
// A GET request to the outbox endpoint returns the activities that were posted to a service’s Outbox. This endpoint is restricted by authorization rules, i.e. the requester must have a valid authorization bearer token or must be verified using HTTP signatures and also must be in the following or witnesses collection. Although, any activity sent to a public URI, is returned without authorization. If no paging parameters are specified in the URL then the response contains information about the outbox collection, i.e. the links to the first and last page, as well as the total number of items in the collection. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: outboxGetResp
func outboxGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters outboxPostReq
type outboxPostReq struct { // nolint: unused,deadcode
	// in: body
	Body vocab.ActivityType
}

// swagger:response outboxPostResp
type outboxPostResp struct { // nolint: unused,deadcode
	// in: body
	Body string
}

//nolint:lll
// outboxPostRequest swagger:route POST /services/orb/outbox ActivityPub outboxPostReq
//
// A POST request to the outbox endpoint adds the activity contained in the request to the service’s Outbox, which will be processed by the ActivityPub Outbox. This endpoint is restricted by authorization rules, i.e. the requester must have a valid authorization bearer token, which is usually an administrator token.
//
// Consumes:
// - application/json
//
// Responses:
//        200: outboxPostResp
func outboxPostRequest() { // nolint: unused,deadcode
}

// swagger:parameters likesGetReq
type likesGetReq struct { // nolint: unused,deadcode
	// In: path
	ID      string `json:"id"`
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response likesGetResp
type likesGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// likesGetRequest swagger:route GET /services/orb/likes/{id} ActivityPub likesGetReq
//
// This endpoint returns a collection of Like activities for a given anchor. If no paging parameters are specified in the URL then the response contains information about the collection, i.e. the links to the first and last page, as well as the total number of items in the collection. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: likesGetResp
func likesGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters likedGetReq
type likedGetReq struct { // nolint: unused,deadcode
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response likedGetResp
type likedGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// likedGetRequest swagger:route GET /services/orb/liked ActivityPub likedGetReq
//
// The anchor events that are liked are returned via this endpoint. (Liked means that the anchors in the response were all added to the ledger.) If no paging parameters are specified in the URL then the response contains information about the collection, i.e. the links to the first and last page, as well as the total number of items in the collection. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: likedGetResp
func likedGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters sharesGetReq
type sharesGetReq struct { // nolint: unused,deadcode
	// In: path
	ID      string `json:"id"`
	Page    bool   `json:"page"`
	PageNum string `json:"page-num"`
}

// swagger:response sharesGetResp
type sharesGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.CollectionType
}

//nolint:lll
// sharesGetRequest swagger:route GET /services/orb/shares/{id} ActivityPub sharesGetReq
//
// The Create activities that were Announced are returned via this endpoint. If no paging parameters are specified in the URL then the response contains information about the collection, i.e. the links to the first and last page, as well as the total number of items in the collection. A subsequent request may be made using parameters that include a specified page number in order to retrieve the actual items.
//
// Produces:
// - application/json
//
// Responses:
//        200: sharesGetResp
func sharesGetRequest() { // nolint: unused,deadcode
}

// swagger:parameters activitiesGetReq
type activitiesGetReq struct { // nolint: unused,deadcode
	// In: path
	ID string `json:"id"`
}

// swagger:response activitiesGetResp
type activitiesGetResp struct { // nolint: unused,deadcode
	// in: body
	Body vocab.ActivityType
}

// activitiesGetRequest swagger:route GET /services/orb/activities/{id} ActivityPub activitiesGetReq
//
// This endpoint returns an activity for the specified ID.
//
// Produces:
// - application/json
//
// Responses:
//        200: activitiesGetResp
func activitiesGetRequest() { // nolint: unused,deadcode
}
