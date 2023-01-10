package bdyp

import (
	"fmt"
	"net/http"
	"net/url"
)

type Bcloud struct {
	app_key      string
	app_secret   string
	accessToken  string
	refreshToken string
	logger       Logger
}

type tokenResp struct {
	*Token
	ErrorDescription string `json:"error_description"`
}

type Token struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

func (r *Bcloud) GetToken(code, redirectURI, app_key, app_secret string) (*Token, error) {
	uri := fmt.Sprintf("https://openapi.baidu.com/oauth/2.0/token?"+
		"grant_type=authorization_code&"+
		"code=%s&"+
		"client_id=%s&"+
		"client_secret=%s&"+
		"redirect_uri=%s",
		url.QueryEscape(code),
		url.QueryEscape(app_key),
		url.QueryEscape(app_secret),
		redirectURI)
	resp := new(tokenResp)

	err := r.requestJSON(http.MethodGet, uri, nil, resp)
	if err != nil {
		return nil, err
	} else if resp.ErrorDescription != "" {
		return nil, fmt.Errorf(resp.ErrorDescription)
	}

	r.app_key = app_key
	r.app_secret = app_secret
	r.accessToken = resp.AccessToken
	r.refreshToken = resp.RefreshToken

	return resp.Token, nil
}
