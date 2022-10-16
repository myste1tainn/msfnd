package middleware

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

type HeaderWithJwt struct {
	Xauthorization string `header:"X-Authorization"`
	Authorization  string `header:"Authorization"`
	Language       string `header:"Accept-Language"`
	CorrelationId  string `header:"X-Correlation-ID"`
	DeviceId       string `header:"X-Device-ID"`
	DeviceModel    string `header:"X-Device-Model"`
	ChannelId      string `header:"X-Channel-ID"`
	ClientVersion  string `header:"X-Client-Version"`
	Platform       string `header:"X-Platform"`
	ForwardedFor   string `header:"X-Forwarded-For"`
	UserAgent      string `header:"User-Agent"`
	Trace          string `header:"trace"`
	SpanId         string `header:"spanId"`
}

func ParseRouteContext() app.AppHandler {
	var logName = "ParseRouteContext"
	return func(ctx app.AppContext) {
		log.Debugf("[debug] %s: activated, going to parse for headers = %s", logName, ctx.Headers())

		var obj HeaderWithJwt
		if err := ctx.BindHeader(&obj); err != nil {
			log.Errorf("[error] %s: parsing for x-authorization & authorization header fails with error %s", logName, err)
			ctx.Error(err)
			return
		}

		if obj.Xauthorization == "" && obj.Authorization == "" {
			msg := fmt.Sprintf("[warn] %s: x-authorization & authorization header does not exists or is in invalid format, RouteContext will not be set", logName)
			log.Warnf(msg)
			ctx.Error(errors.New(msg))
			return
		}

		var auth string = obj.Xauthorization
		if auth == "" {
			auth = obj.Authorization
		}
		jwtTokenString := strings.Replace(auth, "Bearer ", "", 1)
		jwtComponents := strings.Split(jwtTokenString, ".")
		if len(jwtComponents) > 0 && len(jwtComponents) != 3 {
			msg := fmt.Sprintf("[warn] %s: invalid number of components found in jwt %s, RouteContext will not be set", logName, jwtTokenString)
			log.Warnf(msg)
			ctx.Error(errors.New(msg))
			return
		}

		if len(jwtComponents) < 2 {
			msg := fmt.Sprintf("[warn] %s: invalid JWT format %s, RouteContext will not be set", logName, jwtTokenString)
			log.Warnf(msg)
			ctx.Error(errors.New(msg))
			return
		}
		payloadTokenString := jwtComponents[1]
		if i := len(payloadTokenString) % 4; i != 0 {
			payloadTokenString += strings.Repeat("=", 4-i)
		}
		jsonData, err := base64.StdEncoding.DecodeString(payloadTokenString)
		if err != nil {
			log.Errorf("[error] %s: error occurred %s", logName, err)
			ctx.Error(err)
			return
		}

		routeContext := getRouteContxt(ctx)
		err = json.Unmarshal(jsonData, routeContext)
		routeContext.Authorization = auth
		if err != nil {
			log.Errorf("[error] %s: error occurred %s", logName, err)
			ctx.Error(err)
			return
		}

		forwardKeyToRouteContext(obj, routeContext)
		ctx.Set(msfnd.KeyRouteContext, routeContext)
	}
}

func getRouteContxt(ctx app.AppContext) *msfnd.RouteContext {
	if rctx, ok := ctx.Get(msfnd.KeyRouteContext).(*msfnd.RouteContext); !ok {
		return &msfnd.RouteContext{}
	} else {
		return rctx
	}
}

func forwardKeyToRouteContext(obj HeaderWithJwt, rctx *msfnd.RouteContext) {
	if obj.Language != "" {
		rctx.Language = obj.Language
	}
	if obj.CorrelationId != "" {
		rctx.CorrelationId = obj.CorrelationId
	}
	if obj.DeviceId != "" {
		rctx.DeviceId = obj.DeviceId
	}
	if obj.DeviceModel != "" {
		rctx.DeviceModel = obj.DeviceModel
	}
	if obj.ChannelId != "" {
		rctx.ChannelId = obj.ChannelId
	}
	if obj.ClientVersion != "" {
		rctx.ClientVersion = obj.ClientVersion
	}
	if obj.Platform != "" {
		rctx.Platform = obj.Platform
	}
	if obj.ForwardedFor != "" {
		rctx.ForwardedFor = obj.ForwardedFor
	}
	if obj.UserAgent != "" {
		rctx.UserAgent = obj.UserAgent
	}
	if obj.Trace != "" {
		rctx.Trace = obj.Trace
	}
	if obj.SpanId != "" {
		rctx.SpanId = obj.SpanId
	}
}
