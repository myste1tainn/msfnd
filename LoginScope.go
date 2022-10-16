package msfnd

import "strings"

type LoginScope string

var (
	LoginScopeInternal     LoginScope = "internal"
	LoginScopePin          LoginScope = "pin"
	LoginScopeBiometric    LoginScope = "biometric"
	LoginScopeMnp          LoginScope = "mnp"
	LoginScopeEkyc         LoginScope = "ekyc"
	LoginScopeMnpEkyc      LoginScope = "mnp_ekyc"
	LoginScopeRegistration LoginScope = "registration"
	LoginScopeOnboarding   LoginScope = "onboarding"
	LoginScopeOther        LoginScope = "other"
	LoginScopePrelogin     LoginScope = "prelogin"
	LoginScopeResetPin     LoginScope = "resetpin"
	LoginScopeTnc          LoginScope = "tnc"
	LoginScopeExternal     LoginScope = "external"
	LoginScopeBo           LoginScope = "bo"
	LoginScopeLogin        LoginScope = "login"
)

var LoginScopes = []LoginScope{
	LoginScopeInternal,
	LoginScopePin,
	LoginScopeBiometric,
	LoginScopeMnp,
	LoginScopeEkyc,
	LoginScopeMnpEkyc,
	LoginScopeRegistration,
	LoginScopeOnboarding,
	LoginScopeOther,
	LoginScopePrelogin,
	LoginScopeResetPin,
	LoginScopeTnc,
	LoginScopeExternal,
	LoginScopeBo,
	LoginScopeLogin,
}

func (l LoginScope) ClearanceLevel() int {
	switch l {
	case LoginScopePin:
		return 1000
	case LoginScopeBiometric:
		return 500
	case LoginScopePrelogin, LoginScopeLogin:
		return 250
	case LoginScopeExternal, LoginScopeBo:
		return 200
	case LoginScopeResetPin:
		return 225
	case LoginScopeOnboarding, LoginScopeRegistration:
		return 200
	case LoginScopeMnp, LoginScopeEkyc, LoginScopeMnpEkyc, LoginScopeTnc:
		return 100
	case LoginScopeInternal:
		return 0
	case LoginScopeOther:
		return -1
	default:
		return -1000
	}
}

func ParseLoginScope(s string) LoginScope {
	switch strings.ToLower(s) {
	case "internal":
		return LoginScopeInternal
	case "pin":
		return LoginScopePin
	case "biometric":
		return LoginScopeBiometric
	case "mnp":
		return LoginScopeMnp
	case "ekyc":
		return LoginScopeEkyc
	case "mnp_ekyc":
		return LoginScopeMnpEkyc
	case "registration":
		return LoginScopeRegistration
	case "onboarding":
		return LoginScopeOnboarding
	case "prelogin":
		return LoginScopePrelogin
	case "resetpin":
		return LoginScopeResetPin
	case "tnc":
		return LoginScopeTnc
	case "external":
		return LoginScopeExternal
	case "bo":
		return LoginScopeBo
	case "login":
		return LoginScopeLogin
	default:
		return LoginScopeOther
	}
}
