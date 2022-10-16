package msfnd

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/dgrijalva/jwt-go"
	log "github.com/myste1tainn/hexlog"
	"github.com/spf13/viper"
)

var structName = "RouteContext"

type RouteContext struct {
	*jwt.StandardClaims

	// The X-* headers
	Authorization string `header:"X-Authorization,omitempty" json:"X-Authorization,omitempty"`
	DeviceId      string `header:"X-Device-ID,omitempty" json:"X-Device-ID,omitempty"`
	Platform      string `header:"X-Platform,omitempty" json:"X-Platform,omitempty"`
	ClientVersion string `header:"X-Client-Version,omitempty" json:"X-Client-Version,omitempty"`
	ChannelId     string `header:"X-Channel-ID,omitempty" json:"X-Channel-ID,omitempty"`
	DeviceModel   string `header:"X-Device-Model,omitempty" json:"X-Device-Model,omitempty"`
	CorrelationId string `header:"X-Correlation-ID,omitempty" json:"X-Correlation-ID,omitempty"`
	ForwardedFor  string `header:"X-Forwarded-For,omitempty" json:"X-Forwarded-For,omitempty"`

	// The normal http headers
	Language  string `header:"Accept-Language,omitempty" json:"Accept-Language,omitempty"`
	RequestId string `header:"Request-ID,omitempty" json:"requestId,omitempty"`
	UserAgent string `header:"UserAgent,omitempty" json:"userAgent,omitempty"`

	// JWT Payload
	UserRefId      string `json:"userRefId,omitempty"`
	CifNo          string `json:"cifNo,omitempty"`
	Segment        string `json:"segment,omitempty"`
	OtpMobileNo    string `json:"otpMobileNo,omitempty"`
	Cid            string `json:"cid,omitempty"`
	PassportNo     string `json:"passportNo,omitempty"`
	LoginScope     string `json:"loginScope,omitempty"`
	BoUserFullName string `json:"boUserFullName,omitempty"`
	BoUserId       string `json:"boUserId,omitempty"`
	ApiKey         string `json:"apiKey,omitempty"`
	DopaRefId      string `json:"dopaRefId,omitempty"`
	CbsRefId       string `json:"cbsRefId,omitempty"`
	AnyIdReqId     string `json:"anyIdReqId,omitempty"`
	OsVersion      string `json:"osVersion,omitempty"`
	Trace          string `json:"trace,omitempty"`
	SpanId         string `json:"spanId,omitempty"`

	IsDirty bool `json:"-"`

	// There are no supports for this yet in Golang and possibility it will be supported elsewhere, not here
	// when that happends, just delete the lines and this comments
	// standardEvent  string
	// loggerDetails  string

}

func (r *RouteContext) Valid() error {
	return r.StandardClaims.Valid()
}

func (r *RouteContext) repackWithInternalScope() *RouteContext {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, r)

	privateKey := viper.GetString("GCP.SECRET.INTERNAL.JWT.PRIVATE.KEY")
	if !strings.HasPrefix(privateKey, "-----") {
		privateKey = fmt.Sprintf("-----BEGIN PRIVATE KEY-----\n%s\n-----END PRIVATE KEY-----", privateKey)
	}
	privateKeyBlock, _ := pem.Decode([]byte(privateKey))
	if privateKeyBlock == nil {
		log.Errorf("[error] %s: new jwt cannot be generated, private key block decode is nil, privateKey = %s", structName, privateKey)
		return r
	}

	pkcs8Key, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		log.Errorf("[error] %s: new jwt cannot be generated, private key cannot be parsed as PKCS8, error = %v", structName, err)
		return r
	}

	tokenString, err := token.SignedString(pkcs8Key)
	if err != nil {
		log.Errorf("[error] %s: new jwt cannot be generated, signed string cann be yielded = %v", structName, err)
		return r
	}

	if tokenString != "" {
		r.Authorization = "Bearer " + tokenString
	} else {
		log.Errorf("[error] %s: cannot repack, generated token string is empty", structName)
	}

	return r
}

func (r *RouteContext) RepackWithInternalScope() *RouteContext {
	if r.IsDirty {
		r.repackWithInternalScope()
	} else {
		log.Debugf("[debug] %s: data is still pristined jwt is not repacked", structName)
	}
	return r
}

func (r *RouteContext) RepackWithInternalScopeForce() *RouteContext {
	return r.repackWithInternalScope()
}

func (r *RouteContext) SetUserRefId(val string) *RouteContext {
	if r.UserRefId != val {
		r.UserRefId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetCifNo(val string) *RouteContext {
	if r.CifNo != val {
		r.CifNo = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetSegment(val string) *RouteContext {
	if r.Segment != val {
		r.Segment = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetOtpMobileNo(val string) *RouteContext {
	if r.OtpMobileNo != val {
		r.OtpMobileNo = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetCid(val string) *RouteContext {
	if r.Cid != val {
		r.Cid = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetPassportNo(val string) *RouteContext {
	if r.PassportNo != val {
		r.PassportNo = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetLoginScope(val string) *RouteContext {
	if r.LoginScope != val {
		r.LoginScope = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetDeviceId(val string) *RouteContext {
	if r.DeviceId != val {
		r.DeviceId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetBoUserFullName(val string) *RouteContext {
	if r.BoUserFullName != val {
		r.BoUserFullName = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetBoUserId(val string) *RouteContext {
	if r.BoUserId != val {
		r.BoUserId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetLanguage(val string) *RouteContext {
	if r.Language != val {
		r.Language = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetRequestId(val string) *RouteContext {
	if r.RequestId != val {
		r.RequestId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetCorrelationId(val string) *RouteContext {
	if r.CorrelationId != val {
		r.CorrelationId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetForwardedFor(val string) *RouteContext {
	if r.ForwardedFor != val {
		r.ForwardedFor = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetUserAgent(val string) *RouteContext {
	if r.UserAgent != val {
		r.UserAgent = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetPlatform(val string) *RouteContext {
	if r.Platform != val {
		r.Platform = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetClientVersion(val string) *RouteContext {
	if r.ClientVersion != val {
		r.ClientVersion = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetChannelId(val string) *RouteContext {
	if r.ChannelId != val {
		r.ChannelId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetApiKey(val string) *RouteContext {
	if r.ApiKey != val {
		r.ApiKey = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetDopaRefId(val string) *RouteContext {
	if r.DopaRefId != val {
		r.DopaRefId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetCbsRefId(val string) *RouteContext {
	if r.CbsRefId != val {
		r.CbsRefId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetAnyIdReqId(val string) *RouteContext {
	if r.AnyIdReqId != val {
		r.AnyIdReqId = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetDeviceModel(val string) *RouteContext {
	if r.DeviceModel != val {
		r.DeviceModel = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetOsVersion(val string) *RouteContext {
	if r.OsVersion != val {
		r.OsVersion = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetTrace(val string) *RouteContext {
	if r.Trace != val {
		r.Trace = val
		r.IsDirty = true
	}
	return r
}
func (r *RouteContext) SetSpanId(val string) *RouteContext {
	if r.SpanId != val {
		r.SpanId = val
		r.IsDirty = true
	}
	return r
}
