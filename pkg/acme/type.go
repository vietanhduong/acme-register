package acme

import (
	"crypto"
	"fmt"

	"github.com/go-acme/lego/v4/registration"
)

type Configuration struct {
	UserEmail      string // +optional
	UserPrivateKey string // required
	CADirUrl       string //required
}

type User struct {
	Email        string
	key          crypto.PrivateKey
	Registration *registration.Resource
}

func (i *Configuration) Validate() error {
	if i == nil {
		return fmt.Errorf("configuration is required")
	}
	if i.CADirUrl == "" {
		return fmt.Errorf("configuration.ca_dir_url is required")
	}
	if i.UserPrivateKey == "" {
		return fmt.Errorf("configuration.user_private_key is required")
	}
	return nil
}

func (i *User) GetEmail() string {
	return i.Email
}

func (i *User) GetRegistration() *registration.Resource {
	return i.Registration
}

func (i *User) GetPrivateKey() crypto.PrivateKey {
	return i.key
}
