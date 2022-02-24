package internal

import (
	"errors"
	xjwt "mt-iam/internal/jwt"
	"time"

	jwtreq "github.com/golang-jwt/jwt/request"
	"net/http"
)

const (
	jwtAlgorithm = "Bearer"

	// Default JWT token for web handlers is one day.
	defaultJWTExpiry = 24 * time.Hour

	// Inter-node JWT token expiry is 15 minutes.
	defaultInterNodeJWTExpiry = 15 * time.Minute

	// URL JWT token expiry is one minute (might be exposed).
	defaultURLJWTExpiry = time.Minute
)

var (
	errInvalidAccessKeyID = errors.New("The access key ID you provided does not exist in our records")
	errAuthentication     = errors.New("Authentication failed, check your access credentials")
	errNoAuthToken        = errors.New("JWT token missing")
)

// Check if the request is authenticated.
// Returns nil if the request is authenticated. errNoAuthToken if token missing.
// Returns errAuthentication for all other errors.
func webRequestAuthenticate(req *http.Request) (*xjwt.MapClaims, bool, error) {
	token, err := jwtreq.AuthorizationHeaderExtractor.ExtractToken(req)
	if err != nil {
		if err == jwtreq.ErrNoTokenInRequest {
			return nil, false, errNoAuthToken
		}
		return nil, false, err
	}
	claims := xjwt.NewMapClaims()
	if err := xjwt.ParseWithClaims(token, claims, webTokenCallback); err != nil {
		return claims, false, errAuthentication
	}
	owner := claims.AccessKey == globalActiveCred.AccessKey
	return claims, owner, nil
}

// Callback function used for parsing
func webTokenCallback(claims *xjwt.MapClaims) ([]byte, error) {
	if claims.AccessKey == globalActiveCred.AccessKey {
		return []byte(globalActiveCred.SecretKey), nil
	}
	ok, _, err := GlobalIAMSys.IsTempUser(claims.AccessKey)
	if err != nil {
		if err == errNoSuchUser {
			return nil, errInvalidAccessKeyID
		}
		return nil, err
	}
	if ok {
		return []byte(globalActiveCred.SecretKey), nil
	}
	cred, ok := GlobalIAMSys.GetUser(claims.AccessKey)
	if !ok {
		return nil, errInvalidAccessKeyID
	}
	return []byte(cred.SecretKey), nil

}
