package acme

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

type Client struct {
	ctx  context.Context
	cfg  *Configuration
	user *User
}

func NewClient(ctx context.Context, cfg *Configuration) (c *Client, err error) {
	if err = cfg.Validate(); err != nil {
		return nil, err
	}
	c = &Client{ctx: ctx, cfg: cfg}
	if c.user, err = newUser(cfg); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Client) RegisterWithEAB(eabKey, hmacKey string) error {
	legoClient, err := newLegoClient(c.cfg, c.user)
	if err != nil {
		return err
	}
	_, err = legoClient.Registration.RegisterWithExternalAccountBinding(registration.RegisterEABOptions{
		TermsOfServiceAgreed: true,
		Kid:                  eabKey,
		HmacEncoded:          hmacKey,
	})
	return err
}

func newLegoClient(cfg *Configuration, user *User) (client *lego.Client, err error) {
	legoCfg := lego.NewConfig(user)
	legoCfg.Certificate.KeyType = certcrypto.RSA2048
	legoCfg.CADirURL = cfg.CADirUrl
	if client, err = lego.NewClient(legoCfg); err != nil {
		return nil, err
	}
	return client, nil
}

func newUser(cfg *Configuration) (_ *User, err error) {
	var key *rsa.PrivateKey
	if key, err = parseRSAPrivateKey(cfg.UserPrivateKey); err != nil {
		return nil, err
	}
	return &User{Email: cfg.UserEmail, key: key}, nil
}

// parseRSAPrivateKey parse the input private key to rsa.PrivateKey.
func parseRSAPrivateKey(privKey string) (*rsa.PrivateKey, error) {
	blocks, _ := pem.Decode([]byte(privKey))
	key, err := x509.ParsePKCS8PrivateKey(blocks.Bytes)
	if err != nil {
		return nil, err
	}
	return key.(*rsa.PrivateKey), nil
}
