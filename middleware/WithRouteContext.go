package middleware

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/exp/slices"
)

func WithRouteContext(handler func(ctx gin.Context, rctx *msfnd.RouteContext), allowedScopes ...msfnd.LoginScope) gin.Context {
	return withRouteContextFunc(handler, allowedScopes, 0)
}

func WithRouteContextScoped(handler func(ctx gin.Context, rctx *msfnd.RouteContext), invalidScopeHttpErrorCode int, allowedScopes ...msfnd.LoginScope) gin.Context {
	return withRouteContextFunc(handler, allowedScopes, invalidScopeHttpErrorCode)
}

func GetRouteContext(ctx gin.Context) *msfnd.RouteContext {
	return ctx.Get(msfnd.KeyRouteContext).(*msfnd.RouteContext)
}

func withRouteContextFunc(handler func(ctx gin.Context, rctx *msfnd.RouteContext), allowedScopes []msfnd.LoginScope, invalidScopeHttpErrorCode int) gin.Context {
	var logName = "WithRouteContext"
	return func(ctx gin.Context) {
		rctx, ok := ctx.Get(msfnd.KeyRouteContext).(*msfnd.RouteContext)
		if !ok {
			log.Warnf("[warn] %s: WithRouteContext is used but the value cannot be found", logName)
		}

		if len(allowedScopes) != 0 {
			actualScope := msfnd.ParseLoginScope(rctx.LoginScope)
			log.Debugf("validating loginScope = '%v' -> parsedScope = '%v' vs allowedScopes = '%v'", rctx.LoginScope, actualScope, allowedScopes)
			if !slices.Contains(allowedScopes, actualScope) {
				code := invalidScopeHttpErrorCode
				if invalidScopeHttpErrorCode == 0 {
					code = http.StatusForbidden
				}
				err := errors.New(fmt.Sprintf("code %d: wrong scope", code))
				ctx.Error(err)
				return
			}
		}

		handler(ctx, rctx)
	}
}
