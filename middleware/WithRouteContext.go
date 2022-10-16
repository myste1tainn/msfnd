package middleware

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	log "github.com/myste1tainn/hexlog"
	"github.com/myste1tainn/msfnd"
	"golang.org/x/exp/slices"
)

func WithRouteContext(handler func(ctx *gin.Context, rctx *msfnd.RouteContext), allowedScopes ...msfnd.LoginScope) gin.HandlerFunc {
	return withRouteContextFunc(handler, allowedScopes, 0)
}

func WithRouteContextScoped(handler func(ctx *gin.Context, rctx *msfnd.RouteContext), invalidScopeHttpErrorCode int, allowedScopes ...msfnd.LoginScope) gin.HandlerFunc {
	return withRouteContextFunc(handler, allowedScopes, invalidScopeHttpErrorCode)
}

func GetRouteContext(ctx *gin.Context) *msfnd.RouteContext {
	if v, ok := ctx.Get(msfnd.KeyRouteContext); !ok {
		return nil
	} else {
		return v.(*msfnd.RouteContext)
	}
}

func withRouteContextFunc(handler func(ctx *gin.Context, rctx *msfnd.RouteContext), allowedScopes []msfnd.LoginScope, invalidScopeHttpErrorCode int) gin.HandlerFunc {
	var logName = "WithRouteContext"
	return func(ctx *gin.Context) {
		v, ok := ctx.Get(msfnd.KeyRouteContext)
		if !ok {
			log.Warnf("[warn] %s: WithRouteContext is used but the value cannot be found", logName)
		}
		rctx := v.(*msfnd.RouteContext)

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
