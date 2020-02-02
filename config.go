package jwt

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/config/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

// RuleType distinguishes between ALLOW and DENY rules
type RuleType int

const (
	// ALLOW represents a rule that should allow access based on claim value
	ALLOW RuleType = iota

	// DENY represents a rule that should deny access based on claim value
	DENY
)

// EncryptionType specifies the valid configuration for a path
type EncryptionType int

const (
	// HS family of algorithms
	HMAC EncryptionType = iota + 1
	// RS and ES families of algorithms
	PKI
)

// Auth represents configuration information for the middleware
type Auth struct {
	// TODO: Matcher
	AccessRules  []AccessRule  `json:"access_rules,omitempty"`
	Redirect     string        `json:"redirect,omitempty"`
	KeyBackends  []KeyBackend  `json:"key_backends,omitempty"`
	Passthrough  bool          `json:"passthrough"`
	StripHeader  bool          `json:"strip_header"`
	TokenSources []TokenSource `json:"token_sources,omitempty"`
}

// AccessRule represents a single ALLOW/DENY rule based on the value of a claim in
// a validated token
type AccessRule struct {
	Authorize RuleType `json:"authorize"`
	Claim     string   `json:"claim"`
	Value     string   `json:"value"`
}

// CaddyModule returns the Caddy module information.
func (Auth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.jwt",
		New: func() caddy.Module { return new(Auth) },
	}
}

func init() {
	err := caddy.RegisterModule(Auth{})
	httpcaddyfile.RegisterHandlerDirective("jwt", parseCaddyfile)
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//     jwt [<matcher>] {
//         <username> <hashed_password_base64> [<salt_base64>]
//         ...
//     }
//
// If no hash algorithm is supplied, bcrypt will be assumed.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	defaultKeyBackends, err := NewDefaultKeyBackends()
	if err != nil {
		return nil, err
	}

	var r = Auth {
		KeyBackends: defaultKeyBackends
	}

	args := c.RemainingArgs()
	switch len(args) {
	case 0:
		// no argument passed, check the config block
		for c.NextBlock() {
			switch c.Val() {
			case "except":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				r.ExceptedPaths = append(r.ExceptedPaths, c.Val())
				if c.NextArg() {
					// except only allows one path per declaration
					return nil, c.ArgErr()
				}
			case "allowroot":
				r.AllowRoot = true
			case "allow":
				args1 := c.RemainingArgs()
				if len(args1) != 2 {
					return nil, c.ArgErr()
				}
				r.AccessRules = append(r.AccessRules, AccessRule{Authorize: ALLOW, Claim: args1[0], Value: args1[1]})
			case "deny":
				args1 := c.RemainingArgs()
				if len(args1) != 2 {
					return nil, c.ArgErr()
				}
				r.AccessRules = append(r.AccessRules, AccessRule{Authorize: DENY, Claim: args1[0], Value: args1[1]})
			case "redirect":
				args1 := c.RemainingArgs()
				if len(args1) != 1 {
					return nil, c.ArgErr()
				}
				r.Redirect = args1[0]
			case "publickey":
				args1 := c.RemainingArgs()
				if len(args1) != 1 {
					return nil, c.ArgErr()
				}
				backend, err := NewLazyPublicKeyFileBackend(args1[0])
				if err != nil {
					return nil, c.Err(err.Error())
				}
				r.KeyBackends = append(r.KeyBackends, backend)
			case "secret":
				args1 := c.RemainingArgs()
				if len(args1) != 1 {
					return nil, c.ArgErr()
				}
				backend, err := NewLazyHmacKeyBackend(args1[0])
				if err != nil {
					return nil, c.Err(err.Error())
				}
				r.KeyBackends = append(r.KeyBackends, backend)
			case "passthrough":
				r.Passthrough = true
			case "strip_header":
				r.StripHeader = true
			case "token_source":
				args := c.RemainingArgs()
				if len(args) < 1 {
					return nil, c.ArgErr()
				}
				switch args[0] {
				case "header":
					var headerSource = &HeaderTokenSource{
						HeaderName: "Bearer",
					}
					if len(args) == 2 {
						headerSource.HeaderName = args[1]
					} else if len(args) > 2 {
						return nil, c.ArgErr()
					}
					r.TokenSources = append(r.TokenSources, headerSource)
				case "cookie":
					if len(args) != 2 {
						return nil, c.ArgErr()
					}
					r.TokenSources = append(r.TokenSources, &CookieTokenSource{
						CookieName: args[1],
					})
				case "query_param":
					if len(args) != 2 {
						return nil, c.ArgErr()
					}
					r.TokenSources = append(r.TokenSources, &QueryTokenSource{
						ParamName: args[1],
					})
				default:
					return nil, c.Errf("unsupported token_source: '%s'", args[0])
				}
			}
		}
	default:
		// we want only block arguments
		return nil, c.ArgErr()
	}


	// check all rules at least have a path and consistent encryption config
	if r.Path == "" {
		return nil, fmt.Errorf("Each rule must have a path")
	}
	var encType EncryptionType
	for _, e := range r.KeyBackends {
		switch e.(type) {
		case *LazyHmacKeyBackend:
			if encType > 0 && encType != HMAC {
				return nil, fmt.Errorf("Configuration does not have a consistent encryption type for path %s.  Cannot use both HMAC and PKI for a single path value.", r.Path)
			}
			encType = HMAC
		case *LazyPublicKeyBackend:
			if encType > 0 && encType != PKI {
				return nil, fmt.Errorf("Configuration does not have a consistent encryption type for path %s.  Cannot use both HMAC and PKI for a single path value.", r.Path)
			}
			encType = PKI
		}
	}

	return Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"jwt": caddyconfig.JSON(r, nil),
		},
	}, nil
}
