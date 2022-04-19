package main

import (
	"net/http"

	oidc "github.com/coreos/go-oidc"
	"github.com/pkg/errors"
	"golang.org/x/oauth2"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
)

type opaqueTokenAuthenticator struct {
	header        string // header name where opaque access token is stored
	caBundle      []byte
	provider      *oidc.Provider
	oauth2Config  *oauth2.Config
	userIDClaim   string // retrieve the userid claim
	groupsClaim   string // retrieve the groups claim
}

func (s *opaqueTokenAuthenticator) AuthenticateRequest(r *http.Request) (*authenticator.Response, bool, error) {
	logger := loggerForRequest(r, "opaque access token authenticator")

	// get id-token from header
	bearer := getBearerToken(r.Header.Get(s.header))
	if len(bearer) == 0 {
		logger.Info("No bearer token found")
		return nil, false, nil
	}

	opaque := &oauth2.Token {
		AccessToken: bearer,
		TokenType: "access_token",
	}

	ctx := setTLSContext(r.Context(), s.caBundle)

	userInfo, err := GetUserInfo(ctx, s.provider, s.oauth2Config.TokenSource(ctx, opaque))
	if err != nil {
		var reqErr *requestError
		if !errors.As(err, &reqErr) {
			return nil, false, errors.Wrap(err, "UserInfo request failed unexpectedly")
		}
		if reqErr.Response.StatusCode != http.StatusUnauthorized {
			return nil, false, errors.Wrapf(err, "UserInfo request with unexpected code '%d'", reqErr.Response.StatusCode)
		}
		// Access token has expired
		logger.Info("Opaque token has expired")
		opaqueErr := errors.New("Opaque token has expired")

		logger.Info("Attempting to revoke the expired opaque token...")
		_revocationEndpoint, err := revocationEndpoint(s.provider)
		if err != nil {
			opaqueErr = errors.Wrap(opaqueErr,err.Error())
			return nil, false, &authenticatorSpecificError{Err: opaqueErr}
		}

		revocationErr := revokeToken(ctx, _revocationEndpoint, bearer, 
			"access_token", s.oauth2Config.ClientID, s.oauth2Config.ClientSecret)
		if revocationErr != nil {
			opaqueErr = errors.Wrap(opaqueErr,revocationErr.Error())
		}

		return nil, false, &authenticatorSpecificError{Err: opaqueErr}
	}

	// Retrieve the USERID_CLAIM and the GROUPS_CLAIM
	var claims map[string]interface{}
	if claimErr := userInfo.Claims(&claims); claimErr != nil {
		logger.Errorf("Retrieving user claims failed: %v", claimErr)
		return nil, false, &authenticatorSpecificError{Err: claimErr}
	}

	userID, groups, claimErr := s.retrieveUserIDGroupsClaims(claims)
	if claimErr != nil {
		return nil, false, &authenticatorSpecificError{Err: claimErr}
	}

	// Authentication using header successfully completed
	extra := map[string][]string{"auth-method": {"header"}}

	resp := &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   userID,
			Groups: groups,
			Extra:  extra,
		},
	}
	return resp, true, nil
}


// Retrieve the USERID_CLAIM and the GROUPS_CLAIM from the JWT access token
func (s *opaqueTokenAuthenticator) retrieveUserIDGroupsClaims(claims map[string]interface{}) (string, []string, error){
		
	if claims[s.userIDClaim] == nil { 
		claimErr := errors.New("USERID_CLAIM not found in the JWT token")
		return "", []string{}, claimErr
	}

	groups := []string{}
	groupsClaim := claims[s.groupsClaim]
	if groupsClaim == nil {
		claimErr := errors.New("GROUPS_CLAIM not found in the JWT token")
		return "", []string{}, claimErr
	}

	groups = interfaceSliceToStringSlice(groupsClaim.([]interface{}))

	return claims[s.userIDClaim].(string), groups, nil
}

// The Kubernetes Authenticator implements the Cacheable
// interface with the getCacheKey().
func (o *opaqueTokenAuthenticator) getCacheKey(r *http.Request) (string) {
	return getBearerToken(r.Header.Get("Authorization"))

}