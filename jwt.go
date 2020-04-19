package jwt

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	jwt "github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"
)

type TokenSource interface {
	// If the returned string is empty, the token was not found.
	// So far any implementation does not return errors.
	ExtractToken(r *http.Request) string
}

// Extracts a token from the Authorization header in the form `Bearer <JWT Token>`
type HeaderTokenSource struct {
	HeaderName string
}

func (hts *HeaderTokenSource) ExtractToken(r *http.Request) string {
	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == hts.HeaderName && len(jwtHeader) == 2 {
		return jwtHeader[1]
	}
	return ""
}

// Extracts a token from a cookie named `CookieName`.
type CookieTokenSource struct {
	CookieName string
}

func (cts *CookieTokenSource) ExtractToken(r *http.Request) string {
	jwtCookie, err := r.Cookie(cts.CookieName)
	if err == nil {
		return jwtCookie.Value
	}
	return ""
}

// Extracts a token from a URL query parameter of the form https://example.com?ParamName=<JWT token>
type QueryTokenSource struct {
	ParamName string
}

func (qts *QueryTokenSource) ExtractToken(r *http.Request) string {
	jwtQuery := r.URL.Query().Get(qts.ParamName)
	if jwtQuery != "" {
		return jwtQuery
	}
	return ""
}

var (
	// Default TokenSources to be applied in the given order if the
	// user did not explicitly configure them via the token_source option
	DefaultTokenSources = []TokenSource{
		&HeaderTokenSource{
			HeaderName: "Bearer",
		},
		&CookieTokenSource{
			CookieName: "jwt_token",
		},
		&QueryTokenSource{
			ParamName: "token",
		},
	}
)

// Authenticate validates the user credentials in req and returns the user, if valid.
func (h Auth) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	// Always let OPTIONS requests through
	// TODO: Is it correct to pass OPTIONS through as if authentication had succeeded?
	if r.Method == "OPTIONS" {
		return caddyauth.User{}, true, nil
	}

	// strip potentially spoofed claims
	for header := range r.Header {
		if strings.HasPrefix(header, "Token-Claim-") {
			r.Header.Del(header)
		}
	}

	// Path matches, look for unvalidated token
	uToken, err := ExtractToken(h.TokenSources, r)
	if err != nil {
		h.logger.Error("Failed to extract token", zap.Error(err))
		if h.Passthrough {
			return caddyauth.User{}, true, nil
		}
		return handleUnauthorized(w, r, h, h.Realm, nil)
	}

	var vToken *jwt.Token

	if len(h.KeyBackends) <= 0 {
		vToken, err = ValidateToken(uToken, &NoopKeyBackend{})
	}

	// Loop through all possible key files on disk, using cache
	for _, keyBackend := range h.KeyBackends {
		// Validate token
		vToken, err = ValidateToken(uToken, keyBackend.Value)

		if err == nil {
			// break on first correctly validated token
			break
		} else {
			h.logger.Error("Failed to validate token", zap.Error(err))
		}
	}

	// Check last error of validating token.  If error still exists, no keyfiles matched
	if err != nil || vToken == nil {
		return caddyauth.User{}, h.Passthrough, nil
	}

	vClaims, err := Flatten(vToken.Claims.(jwt.MapClaims), "", DotStyle)
	if err != nil {
		h.logger.Error("Failed to flatten claims", zap.Error(err))
		return handleUnauthorized(w, r, h, h.Realm, nil)
	}

	// If token contains rules with allow or deny, evaluate
	if len(h.AccessRules) > 0 {
		var isAuthorized []bool
		for _, rule := range h.AccessRules {
			v := vClaims[rule.Claim]
			ruleMatches := contains(v, rule.Value) || v == rule.Value
			switch rule.Authorize {
			case ALLOW:
				isAuthorized = append(isAuthorized, ruleMatches)
			case DENY:
				isAuthorized = append(isAuthorized, !ruleMatches)
			default:
				h.logger.Error("Unknown rule type for claim", zap.String("claim", rule.Claim), zap.Int("Authorize", (int)(rule.Authorize)))
				return handleUnauthorized(w, r, h, h.Realm, fmt.Errorf("unknown rule type"))
			}
		}
		// test all flags, if any are true then ok to pass
		ok := false
		for _, result := range isAuthorized {
			if result {
				ok = true
			}
		}
		if !ok {
			h.logger.Error("No valid token provided.")
			return handleForbidden(w, r, h, h.Realm, nil)
		}
	}

	var (
		claim string
		value string
	)

	// set claims as separate headers for downstream to consume
	for claim, value := range vClaims {
		var headerName string
		switch h.StripHeader {
		case true:
			stripped := strings.SplitAfter(claim, "/")
			finalStrip := stripped[len(stripped)-1]
			headerName = "Token-Claim-" + modTitleCase(finalStrip)
		default:
			escaped := url.PathEscape(claim)
			headerName = "Token-Claim-" + modTitleCase(escaped)
		}

		switch v := value.(type) {
		case string:
			r.Header.Set(headerName, v)
		case int64:
			r.Header.Set(headerName, strconv.FormatInt(v, 10))
		case bool:
			r.Header.Set(headerName, strconv.FormatBool(v))
		case int32:
			r.Header.Set(headerName, strconv.FormatInt(int64(v), 10))
		case float32:
			r.Header.Set(headerName, strconv.FormatFloat(float64(v), 'f', -1, 32))
		case float64:
			r.Header.Set(headerName, strconv.FormatFloat(v, 'f', -1, 64))
		case []interface{}:
			b := bytes.NewBufferString("")
			for i, item := range v {
				if i > 0 {
					b.WriteString(",")
				}
				b.WriteString(fmt.Sprintf("%v", item))
			}
			r.Header.Set(headerName, b.String())
		default:
			// ignore, because, JWT spec says in https://tools.ietf.org/html/rfc7519#section-4
			//     all claims that are not understood
			//     by implementations MUST be ignored.
		}
	}

	// If we got there, we're good
	return caddyauth.User{ID: claim + "-" + value}, true, nil
}

// ExtractToken will find a JWT token in the token sources specified.
// If tss is empty, the DefaultTokenSources are used.
func ExtractToken(tss []TokenSource, r *http.Request) (string, error) {

	effectiveTss := tss
	if len(effectiveTss) == 0 {
		// Defaults are applied here as this keeps the tests the cleanest.
		effectiveTss = DefaultTokenSources
	}

	for _, tss := range effectiveTss {
		token := tss.ExtractToken(r)
		if token != "" {
			return token, nil
		}
	}

	return "", fmt.Errorf("no token found")
}

// ValidateToken will return a parsed token if it passes validation, or an
// error if any part of the token fails validation.  Possible errors include
// malformed tokens, unknown/unspecified signing algorithms, missing secret key,
// tokens that are not valid yet (i.e., 'nbf' field), tokens that are expired,
// and tokens that fail signature verification (forged)
func ValidateToken(uToken string, keyBackend KeyBackend) (*jwt.Token, error) {
	if len(uToken) == 0 {
		return nil, fmt.Errorf("Token length is zero")
	}
	token, err := jwt.Parse(uToken, keyBackend.ProvideKey)

	if err != nil {
		return nil, err
	}

	return token, nil
}

// handleUnauthorized checks, which action should be performed if access was denied.
// It returns the status code and writes the Location header in case of a redirect.
// Possible caddy variables in the location value will be substituted.
func handleUnauthorized(w http.ResponseWriter, r *http.Request, rule Auth, realm string, err error) (caddyauth.User, bool, error) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"%s\",error=\"invalid_token\"", realm))
	return caddyauth.User{}, false, err
}

// handleForbidden checks, which action should be performed if access was denied.
// It returns the status code and writes the Location header in case of a redirect.
// Possible caddy variables in the location value will be substituted.
func handleForbidden(w http.ResponseWriter, r *http.Request, rule Auth, realm string, err error) (caddyauth.User, bool, error) {
	w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer realm=\"%s\",error=\"insufficient_scope\"", realm))
	return caddyauth.User{}, false, err
}

// contains checks weather list is a slice ans containts the
// supplied string value.
func contains(list interface{}, value string) bool {
	switch l := list.(type) {
	case []interface{}:
		for _, v := range l {
			if v == value {
				return true
			}
		}
	}
	return false
}

func modTitleCase(s string) string {
	switch {
	case len(s) == 0:
		return s
	case len(s) == 1:
		return strings.ToUpper(s)
	default:
		return strings.ToUpper(string(s[0])) + s[1:]
	}
}
