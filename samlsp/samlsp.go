// Package samlsp provides helpers that can be used to protect web
// services using SAML.
package samlsp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"github.com/crewjam/saml/logger"
	"github.com/thaniyarasu/saml"
	"io/ioutil"
	"net/http"
	"os"
	"time"
)

const defaultTokenMaxAge = time.Hour / 2

// Options represents the parameters for creating a new middleware
type Options struct {
	Key               *rsa.PrivateKey
	Logger            logger.Interface
	Certificate       *x509.Certificate
	AllowIDPInitiated bool
	IDPMetadata       *saml.EntityDescriptor
	HTTPClient        *http.Client
	CookieMaxAge      time.Duration
	CookieName        string
	CookieDomain      string
	CookieSecure      bool
	ForceAuthn        bool
}

// New creates a new Middleware
func New(opts Options) (*Middleware, error) {

	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}

	fmt.Println("====================opts.CookieMaxAge===================")
	fmt.Println(opts.CookieMaxAge)
	fmt.Println(defaultTokenMaxAge)

	tokenMaxAge := opts.CookieMaxAge
	if opts.CookieMaxAge == 0 {
		tokenMaxAge = defaultTokenMaxAge
	}

	m := &Middleware{
		ServiceProvider: saml.ServiceProvider{
			Key:         opts.Key,
			Logger:      logr,
			Certificate: opts.Certificate,

			IDPMetadata: opts.IDPMetadata,
			ForceAuthn:  &opts.ForceAuthn,
		},
		AllowIDPInitiated: opts.AllowIDPInitiated,
		TokenMaxAge:       tokenMaxAge,
	}

	cookieStore := ClientCookies{
		ServiceProvider: &m.ServiceProvider,
		Name:            defaultCookieName,
		//Domain:          opts.URL.Host,
		Secure: opts.CookieSecure,
	}
	m.ClientState = &cookieStore
	m.ClientToken = &cookieStore

	pwd, _ := os.Getwd()
	data, _ := ioutil.ReadFile(pwd + "/" + os.Getenv("IDPXML"))
	fmt.Print(string(data))

	entity := &saml.EntityDescriptor{}
	err := xml.Unmarshal(data, entity)

	// this comparison is ugly, but it is how the error is generated in encoding/xml
	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}

		err = fmt.Errorf("no entity found with IDPSSODescriptor")
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				entity = &entities.EntityDescriptors[i]
				err = nil
			}
		}
	}
	if err != nil {
		return nil, err
	}

	m.ServiceProvider.IDPMetadata = entity
	return m, nil
}
