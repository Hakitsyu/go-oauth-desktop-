package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

func main() {
	config := &OAuthAuthenticatorConfig{
		ClientId:     "",
		ClientSecret: "",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Urls: &OAuthAuthenticatorConfigUrls{
			AuthorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
			AccessTokenEndpoint:   "https://oauth2.googleapis.com/token",
		},
	}

	challenger := NewOAuthAuthenticatorS256Challenger()

	authenticator := NewOAuthAuthenticator(config, challenger)

	accessToken, err := authenticator.Authenticate()
	if err != nil {
		panic(err)
	}

	fmt.Printf("Access token: %s\n", accessToken)
}

type OAuthAuthenticatorConfig struct {
	ClientId     string
	ClientSecret string
	Scopes       []string
	Urls         *OAuthAuthenticatorConfigUrls
}

type OAuthAuthenticatorConfigUrls struct {
	AuthorizationEndpoint string
	AccessTokenEndpoint   string
}

type OAuthAuthenticator struct {
	config     *OAuthAuthenticatorConfig
	challenger OAuthAuthenticatorChallenger
}

func NewOAuthAuthenticator(
	config *OAuthAuthenticatorConfig,
	challenger OAuthAuthenticatorChallenger,
) *OAuthAuthenticator {
	return &OAuthAuthenticator{
		config:     config,
		challenger: challenger,
	}
}

func (o *OAuthAuthenticator) Authenticate() (string, error) {
	redirectUri, code := o.listenRedirectUriCode()

	codeVerifier, err := o.challenger.GetVerifier()
	if err != nil {
		return "", err
	}

	codeChallenge := o.challenger.GetChallenge(codeVerifier)
	codeChallengeMethod := o.challenger.GetMethod()

	authorizationUrl, err := o.generateAuthorizationUrl(
		redirectUri,
		codeChallenge,
		codeChallengeMethod,
	)
	if err != nil {
		return "", err
	}

	fmt.Printf("Opening browser to %s\n", authorizationUrl)
	OpenBrowser(authorizationUrl)

	accessToken, err := o.getAccessToken(
		redirectUri,
		<-code,
		codeVerifier,
	)
	if err != nil {
		return "", err
	}

	return accessToken, nil
}

func (o *OAuthAuthenticator) listenRedirectUriCode() (string, chan string) {
	code := make(chan (string))

	listener := NewHttpListener()
	listener.Serve(func(w http.ResponseWriter, r *http.Request) {
		currentCode := r.URL.Query().Get("code")
		if currentCode != "" {
			code <- currentCode
			listener.Close(context.Background())
		}
	})

	redirectUri := fmt.Sprintf("http://localhost:%d", listener.serverPort)

	fmt.Printf("Listening code on %s\n", redirectUri)

	return redirectUri, code
}

func (o *OAuthAuthenticator) generateAuthorizationUrl(
	redirectUri string,
	codeChallenge string,
	codeChallengeMethod string,
) (string, error) {
	currentUrl, err := url.Parse(o.config.Urls.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}

	query := url.Values{}
	query.Set("client_id", o.config.ClientId)
	query.Set("scope", strings.Join(o.config.Scopes, " "))
	query.Add("code_challenge", codeChallenge)
	query.Add("code_challenge_method", codeChallengeMethod)
	query.Add("redirect_uri", redirectUri)
	query.Add("response_type", "code")
	currentUrl.RawQuery = query.Encode()

	return currentUrl.String(), nil
}

func (o *OAuthAuthenticator) getAccessToken(
	redirectUri string,
	code string,
	codeVerifier string,
) (string, error) {
	client := &http.Client{
		Timeout: time.Minute,
	}

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", o.config.ClientId)
	data.Set("client_secret", o.config.ClientSecret)
	data.Set("code_verifier", codeVerifier)
	data.Set("code", code)
	data.Set("redirect_uri", redirectUri)
	encodedData := data.Encode()

	req, err := http.NewRequest(
		"POST",
		o.config.Urls.AccessTokenEndpoint,
		strings.NewReader(encodedData),
	)
	if err != nil {
		return "", nil
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", fmt.Sprintf("%d", len(encodedData)))

	res, err := client.Do(req)
	if err != nil {
		return "", err
	}

	defer res.Body.Close()

	var body map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		return "", err
	}

	return body["access_token"].(string), nil
}

type OAuthAuthenticatorChallenger interface {
	GetMethod() string
	GetVerifier() (string, error)
	GetChallenge(verifier string) string
}

type OAuthAuthenticatorS256Challenger struct {
}

func NewOAuthAuthenticatorS256Challenger() *OAuthAuthenticatorS256Challenger {
	return &OAuthAuthenticatorS256Challenger{}
}

func (o *OAuthAuthenticatorS256Challenger) GetMethod() string {
	return "S256"
}

func (o *OAuthAuthenticatorS256Challenger) GetVerifier() (string, error) {
	const length int = 64

	verifier := make([]byte, length)
	_, err := rand.Read(verifier)
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(verifier), nil
}

func (o *OAuthAuthenticatorS256Challenger) GetChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))

	return base64.RawURLEncoding.EncodeToString(hash[:])
}

type HttpListener struct {
	isServed   bool
	serverPort int
	server     *http.Server
}

func NewHttpListener() *HttpListener {
	return &HttpListener{}
}

func (l *HttpListener) Serve(callback func(http.ResponseWriter, *http.Request)) error {
	server := &http.Server{}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		callback(w, r)
	})

	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		return err
	}

	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			panic(err)
		}
	}()

	l.server = server
	l.serverPort = listener.Addr().(*net.TCPAddr).Port

	return nil
}

func (l *HttpListener) Close(ctx context.Context) error {
	if err := l.server.Shutdown(ctx); err != nil {
		return err
	}

	l.server = nil
	l.serverPort = 0

	return nil
}

func OpenBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	default:
		return errors.New("Unsupported platform")
	}

	return cmd.Start()
}
