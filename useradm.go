// Copyright 2016 Mender Software AS
//
//    Licensed under the Apache License, Version 2.0 (the "License");
//    you may not use this file except in compliance with the License.
//    You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
//    Unless required by applicable law or agreed to in writing, software
//    distributed under the License is distributed on an "AS IS" BASIS,
//    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//    See the License for the specific language governing permissions and
//    limitations under the License.
package main

import (
	"time"

	"github.com/pkg/errors"
	"github.com/satori/go.uuid"
)

var (
	ErrUnauthorized   = errors.New("unauthorized")
	ErrUserNotInitial = errors.New("user databse not empty")
)

type UserAdmApp interface {
	// Login accepts email/password, returns JWT
	Login(email, pass string) (*Token, error)
	CreateUser(u *UserModel) error
	CreateUserInitial(u *UserModel) error

	SignToken() SignFunc
}

type UserAdmConfig struct {
	Issuer         string
	ExpirationTime int64
}

type UserAdm struct {
	jwtHandler JWTHandler
	db         DataStore
	config     UserAdmConfig
}

func NewUserAdm(jwtHandler JWTHandler, db DataStore, config UserAdmConfig) *UserAdm {
	return &UserAdm{
		jwtHandler: jwtHandler,
		db:         db,
		config:     config,
	}
}

// this is a dummy method for now - always returns a valid JWT; no db interaction
func (u *UserAdm) Login(email, pass string) (*Token, error) {

	if email == "" && pass == "" {
		empty, err := u.db.IsEmpty()
		if err != nil {
			return nil, errors.Wrap(err, "useradm: failed to query database")
		}
		if !empty {
			return nil, ErrUnauthorized
		}
		// initial login
		t := u.generateInitialToken()

		return t, nil
	}

	return nil, nil
}

func (u *UserAdm) generateInitialToken() *Token {
	return &Token{
		Claims: Claims{
			Id:        uuid.NewV4().String(),
			Issuer:    u.config.Issuer,
			ExpiresAt: time.Now().Unix() + u.config.ExpirationTime,
			Subject:   "initial",
			Scope:     ScopeInitialUserCreate,
		},
	}
}

func (u *UserAdm) SignToken() SignFunc {
	return func(t *Token) (string, error) {
		return u.jwtHandler.ToJWT(t)
	}
}

func (ua *UserAdm) CreateUser(u *UserModel) error {
	u.ID = uuid.NewV4().String()

	return ua.db.CreateUser(u)
}

func (ua *UserAdm) CreateUserInitial(u *UserModel) error {
	empty, err := ua.db.IsEmpty()
	if err != nil {
		return errors.Wrap(err, "failed to check if db is empty")
	}

	if empty {
		return ua.CreateUser(u)
	} else {
		return ErrUserNotInitial
	}
}
