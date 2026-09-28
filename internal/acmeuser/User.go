package acmeuser

import (
	"crypto"

	"github.com/go-acme/lego/v4/registration"
)

// User implements registration.User, the minimal identity lego.NewClient and
// registration.Registrar need: an account contact, its private key, and - once registered -
// the account's registration resource.
type User struct {
	Email        string
	PrivateKey   crypto.PrivateKey
	Registration *registration.Resource
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.PrivateKey
}
