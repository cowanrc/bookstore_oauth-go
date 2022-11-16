package oauth

import (
	"bookstore_oauth-go/oauth/errors"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mercadolibre/golang-restclient/rest"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8080",
		Timeout: 200 * time.Microsecond,
	}
)

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}

	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}

	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}

	return clientId
}

func AuthenticateRequest(request *http.Request) *errors.RestErr {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))

	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}

	request.Header.Del(headerXCallerId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	fmt.Print("Here")
	response := oauthRestClient.Get(fmt.Sprintf("oauth/access_token/%s", accessTokenId))

	if response == nil || response.Response == nil {
		return nil, errors.NewInternalServerError("Here invalid restclient response when trying to access token")
	}

	if response.StatusCode > 299 {
		var restErr errors.RestErr
		if err := json.Unmarshal(response.Bytes(), &restErr); err != nil {
			fmt.Println("here")
			return nil, errors.NewInternalServerError("here 2 invalid restclient response when trying to access token")
		}
		return nil, &restErr
	}

	var at accessToken
	if err := json.Unmarshal(response.Bytes(), &at); err != nil {
		return nil, errors.NewInternalServerError("error when trying to unmarshal access token response")
	}
	return &at, nil
}
