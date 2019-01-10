package samlsp

import (
	//"crypto/x509"
	"encoding/base64"
	//"encoding/xml"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"github.com/thaniyarasu/saml"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type UserType struct {
	UserType string
}

var user_types []UserType

var OnboardingRoles = "Super Admin,Notification Admin"

type User struct {
	gorm.Model
	UserId string
}

func (User) TableName() string {
	return os.Getenv("AUTH_TABLE_NAME")
}

// Middleware implements middleware than allows a web application
// to support SAML.
//
// It implements http.Handler so that it can provide the metadata and ACS endpoints,
// typically /saml/metadata and /saml/acs, respectively.
//
// It also provides middleware RequireAccount which redirects users to
// the auth process if they do not have session credentials.
//
// When redirecting the user through the SAML auth flow, the middlware assigns
// a temporary cookie with a random name beginning with "saml_". The value of
// the cookie is a signed JSON Web Token containing the original URL requested
// and the SAML request ID. The random part of the name corresponds to the
// RelayState parameter passed through the SAML flow.
//
// When validating the SAML response, the RelayState is used to look up the
// correct cookie, validate that the SAML request ID, and redirect the user
// back to their original URL.
//
// Sessions are established by issuing a JSON Web Token (JWT) as a session
// cookie once the SAML flow has succeeded. The JWT token contains the
// authenticated attributes from the SAML assertion.
//
// When the middlware receives a request with a valid session JWT it extracts
// the SAML attributes and modifies the http.Request object adding a Context
// object to the request context that contains attributes from the initial
// SAML assertion.
//
// When issuing JSON Web Tokens, a signing key is required. Because the
// SAML service provider already has a private key, we borrow that key
// to sign the JWTs as well.
type Middleware struct {
	ServiceProvider   saml.ServiceProvider
	AllowIDPInitiated bool
	TokenMaxAge       time.Duration
	ClientState       ClientState
	ClientToken       ClientToken
	Binding           string
	DB                *gorm.DB
}

var jwtSigningMethod = jwt.SigningMethodHS256
var secretBlock = []byte(os.Getenv("SECRET"))

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

// ServeHTTP implements http.Handler and serves the SAML-specific HTTP endpoints
// on the URIs specified by m.ServiceProvider.MetadataURL and
// m.ServiceProvider.AcsURL.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Println("===============ServerHTTP============")
	// block metadata
	// if r.URL.Path == m.ServiceProvider.MetadataURL.Path {
	// 	buf, _ := xml.MarshalIndent(m.ServiceProvider.Metadata(), "", "  ")
	// 	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	// 	w.Write(buf)
	// 	return
	// }
	fmt.Println(r.URL.Path)
	fmt.Println(m.ServiceProvider.AcsURL.Path)
	//r.URL.Path == m.ServiceProvider.AcsURL.Path

	if true {
		fmt.Println("entered")
		r.ParseForm()
		assertion, err := m.ServiceProvider.ParseResponse(r, m.getPossibleRequestIDs(r))
		if err != nil {
			if parseErr, ok := err.(*saml.InvalidResponseError); ok {
				m.ServiceProvider.Logger.Printf("RESPONSE: ===\n%s\n===\nNOW: %s\nERROR: %s",
					parseErr.Response, parseErr.Now, parseErr.PrivateErr)
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		m.Authorize(w, r, assertion)
		return
	}

	http.NotFoundHandler().ServeHTTP(w, r)
}

// RequireAccount is HTTP middleware that requires that each request be
// associated with a valid session. If the request is not associated with a valid
// session, then rather than serve the request, the middlware redirects the user
// to start the SAML auth flow.
func (m *Middleware) setup(r *http.Request) error {
	var rootURL *url.URL
	rootURL, _ = url.Parse(r.Referer())

	// if strings.Contains(r.Referer(), "localhost") {
	// } else {
	// 	rootURL, _ = url.Parse("https://" + r.Referer())
	// }

	acsURL := *rootURL
	metadataURL := *rootURL
	acsURL.Path = acsURL.Path + os.Getenv("ACS_PATH")
	metadataURL.Path = metadataURL.Path + os.Getenv("META_PATH")

	m.ServiceProvider.MetadataURL = metadataURL
	m.ServiceProvider.AcsURL = acsURL
	//m.ClientState.Domain = r.Host
	//m.ClientToken.Domain = r.Host

	// fmt.Println("===================")
	// fmt.Println(metadataURL.Host)
	// fmt.Println(acsURL.Host)
	// fmt.Println(r.URL.Path)
	// fmt.Println(r.URL.RawPath)
	// fmt.Println(r.URL.String())
	// fmt.Println(r.URL.Host)

	fmt.Println("===================")
	fmt.Println(rootURL)
	fmt.Println(acsURL)
	fmt.Println(r.Host)
	fmt.Println(r.Referer())
	fmt.Println("===================")
	return nil
}

func (m *Middleware) RequireAccount(handler http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if token := m.GetAuthorizationToken(r); token != nil {
			//fmt.Println(token)
			//fmt.Println(r.Context())
			//fmt.Println(WithToken(r.Context(), token))
			r = r.WithContext(WithToken(r.Context(), token))
			handler.ServeHTTP(w, r)
			return
		}
		//fmt.Println("======================")
		if err := m.setup(r); err != nil {
			panic("setup failed")
		}

		// If we try to redirect when the original request is the ACS URL we'll
		// end up in a loop. This is a programming error, so we panic here. In
		// general this means a 500 to the user, which is preferable to a
		// redirect loop.
		if r.URL.Path == m.ServiceProvider.AcsURL.Path {
			panic("don't wrap Middleware with RequireAccount")
		}

		var binding, bindingLocation string
		if m.Binding != "" {
			binding = m.Binding
			bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		} else {
			binding = saml.HTTPRedirectBinding
			bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
			if bindingLocation == "" {
				binding = saml.HTTPPostBinding
				bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
			}
		}

		req, err := m.ServiceProvider.MakeAuthenticationRequest(bindingLocation)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Println("===========================MAKEAuthFROm middleware=============")
		fmt.Println(req)

		// relayState is limited to 80 bytes but also must be integrety protected.
		// this means that we cannot use a JWT because it is way to long. Instead
		// we set a cookie that corresponds to the state
		relayState := base64.URLEncoding.EncodeToString(randomBytes(42))

		//secretBlock := x509.MarshalPKCS1PrivateKey(m.ServiceProvider.Key)
		state := jwt.New(jwtSigningMethod)
		claims := state.Claims.(jwt.MapClaims)
		claims["id"] = req.ID
		claims["uri"] = r.URL.String()
		//fmt.Println(claims["id"])
		//fmt.Println(claims["uri"])
		//fmt.Println(binding)

		signedState, err := state.SignedString(secretBlock)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		m.ClientState.SetState(w, r, relayState, signedState)

		if binding == saml.HTTPRedirectBinding {
			fmt.Println("saml.HTTPRedirectBinding")
			redirectURL := req.Redirect(relayState)
			//fmt.Println(redirectURL)

			fmt.Println(redirectURL.String())

			w.Header().Add("Location", redirectURL.String())
			w.WriteHeader(http.StatusFound)
			return
		}

		if binding == saml.HTTPPostBinding {
			fmt.Println("saml.HTTPPostBinding")

			w.Header().Add("Content-Security-Policy", ""+
				"default-src; "+
				"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
				"reflected-xss block; referrer no-referrer;")
			w.Header().Add("Content-type", "text/html")
			w.Write([]byte(`<!DOCTYPE html><html><body>`))
			w.Write(req.Post(relayState))
			w.Write([]byte(`</body></html>`))
			return
		}
		panic("not reached")
	}
	return http.HandlerFunc(fn)
}

func (m *Middleware) getPossibleRequestIDs(r *http.Request) []string {
	rv := []string{}
	for _, value := range m.ClientState.GetStates(r) {
		jwtParser := jwt.Parser{
			ValidMethods: []string{jwtSigningMethod.Name},
		}
		token, err := jwtParser.Parse(value, func(t *jwt.Token) (interface{}, error) {
			//secretBlock := x509.MarshalPKCS1PrivateKey(m.ServiceProvider.Key)
			return secretBlock, nil
		})
		if err != nil || !token.Valid {
			m.ServiceProvider.Logger.Printf("... invalid token %s", err)
			continue
		}
		claims := token.Claims.(jwt.MapClaims)
		rv = append(rv, claims["id"].(string))
	}

	// If IDP initiated requests are allowed, then we can expect an empty response ID.
	if m.AllowIDPInitiated {
		rv = append(rv, "")
	}

	return rv
}

// Authorize is invoked by ServeHTTP when we have a new, valid SAML assertion.
// It sets a cookie that contains a signed JWT containing the assertion attributes.
// It then redirects the user's browser to the original URL contained in RelayState.
func (m *Middleware) Authorize(w http.ResponseWriter, r *http.Request, assertion *saml.Assertion) {
	//secretBlock := x509.MarshalPKCS1PrivateKey(m.ServiceProvider.Key)
	fmt.Println("============Authorize===============")
	fmt.Println("============assertion===============")

	fmt.Println(assertion)

	//redirectURI := "/"
	if relayState := r.Form.Get("RelayState"); relayState != "" {
		stateValue := m.ClientState.GetState(r, relayState)
		if stateValue == "" {
			m.ServiceProvider.Logger.Printf("cannot find corresponding state: %s", relayState)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		jwtParser := jwt.Parser{
			ValidMethods: []string{jwtSigningMethod.Name},
		}
		state, err := jwtParser.Parse(stateValue, func(t *jwt.Token) (interface{}, error) {
			return secretBlock, nil
		})
		if err != nil || !state.Valid {
			m.ServiceProvider.Logger.Printf("Cannot decode state JWT: %s (%s)", err, stateValue)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		claims := state.Claims.(jwt.MapClaims)
		fmt.Println("================claims==============")
		fmt.Println(claims)
		//redirectURI = claims["uri"].(string)

		// delete the cookie
		m.ClientState.DeleteState(w, r, relayState)
	}

	now := saml.TimeNow()
	// claims := AuthorizationToken{}
	// claims.Audience = m.ServiceProvider.Metadata().EntityID
	// claims.IssuedAt = now.Unix()
	// claims.ExpiresAt = now.Add(m.TokenMaxAge).Unix()
	// claims.NotBefore = now.Unix()

	//uid := assertion.Subject.NameID.Value
	uid := strings.ToUpper(assertion.Subject.NameID.Value)
	fmt.Println("================uid==============")
	fmt.Println(uid)

	m.DB.Table("mlmuser.user_type").Select("distinct user_type").Where("user_id = ?", uid).Scan(&user_types)

	//email := convert_to_email(uid)
	//roles := assertion.Subject.Roles.Value
	roles := []string{"user", "devop"}
	path := "/?"

	for _, e := range user_types {
		roles = append(roles, e.UserType)
	}
	for _, e := range roles {
		if strings.Contains(OnboardingRoles, e) {
			path = "/onboarding/index.html?"
			break
		}
	}
	standardClaims := jwt.StandardClaims{
		Audience: m.ServiceProvider.Metadata().EntityID,
		IssuedAt: now.Unix(),

		ExpiresAt: now.Add(m.TokenMaxAge).Unix(),
		//ExpiresAt: now.Add(time.Minute * 60).Unix(),

		NotBefore: now.Unix(),
		Id:        uid,
	}
	claims := AuthorizationToken{uid, roles, standardClaims, map[string][]string{}}
	m.DB.FirstOrCreate(&User{}, User{UserId: uid})

	if sub := assertion.Subject; sub != nil {
		if nameID := sub.NameID; nameID != nil {
			claims.StandardClaims.Subject = nameID.Value
		}
	}
	for _, attributeStatement := range assertion.AttributeStatements {
		//claims.Attributes = map[string][]string{}
		for _, attr := range attributeStatement.Attributes {
			claimName := attr.FriendlyName
			if claimName == "" {
				claimName = attr.Name
			}
			for _, value := range attr.Values {
				claims.Attributes[claimName] = append(claims.Attributes[claimName], value.Value)
			}
		}
	}
	signedToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secretBlock)
	if err != nil {
		panic(err)
	}

	m.ClientToken.SetToken(w, r, signedToken, m.TokenMaxAge)
	ruri := path + AKEY + "=" + signedToken

	http.Redirect(w, r, ruri, http.StatusFound)
}

// IsAuthorized returns true if the request has already been authorized.
//
// Note: This function is retained for compatability. Use GetAuthorizationToken in new code
// instead.
func (m *Middleware) IsAuthorized(r *http.Request) bool {
	return m.GetAuthorizationToken(r) != nil
}

// GetAuthorizationToken is invoked by RequireAccount to determine if the request
// is already authorized or if the user's browser should be redirected to the
// SAML login flow. If the request is authorized, then the request context is
// ammended with a Context object.
func (m *Middleware) GetAuthorizationToken(r *http.Request) *AuthorizationToken {
	tokenStr := m.ClientToken.GetToken(r)
	if tokenStr == "" {
		return nil
	}

	tokenClaims := AuthorizationToken{}
	token, err := jwt.ParseWithClaims(tokenStr, &tokenClaims, func(t *jwt.Token) (interface{}, error) {
		//secretBlock := x509.MarshalPKCS1PrivateKey(m.ServiceProvider.Key)
		return secretBlock, nil
	})

	if claims, ok := token.Claims.(*AuthorizationToken); ok && token.Valid {
		fmt.Printf("%v %v", claims.UserId, claims.StandardClaims.ExpiresAt)
	} else {
		fmt.Println(err)
	}

	if err != nil || !token.Valid {
		m.ServiceProvider.Logger.Printf("ERROR: invalid token: %s", err)
		return nil
	}
	if err := tokenClaims.StandardClaims.Valid(); err != nil {
		m.ServiceProvider.Logger.Printf("ERROR: invalid token claims: %s", err)
		return nil
	}
	// if tokenClaims.Audience != m.ServiceProvider.Metadata().EntityID {
	// 	m.ServiceProvider.Logger.Printf("ERROR: tokenClaims.Audience does not match EntityID")
	// 	return nil
	// }

	return &tokenClaims
}

// RequireAttribute returns a middleware function that requires that the
// SAML attribute `name` be set to `value`. This can be used to require
// that a remote user be a member of a group. It relies on the Claims assigned
// to to the context in RequireAccount.
//
// For example:
//
//     goji.Use(m.RequireAccount)
//     goji.Use(RequireAttributeMiddleware("eduPersonAffiliation", "Staff"))
//
func RequireAttribute(name, value string) func(http.Handler) http.Handler {
	return func(handler http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			if claims := Token(r.Context()); claims != nil {
				for _, actualValue := range claims.Attributes[name] {
					if actualValue == value {
						handler.ServeHTTP(w, r)
						return
					}
				}
			}
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		}
		return http.HandlerFunc(fn)
	}
}

// func convert_to_email( e string) string {
// 	is_valid_email := false
// 	if a := strings.Split(e, "@"); len(a) == 2 {
// 		if a0 := strings.Split( a[1] ,  "."); len(a0) == 2 {
// 			is_valid_email = true
// 		}
// 	}
// 	if !is_valid_email {
// 		e = e +"@" + os.Getenv("EMAIL_DOMAIN")
// 	}
// 	return e
// }
