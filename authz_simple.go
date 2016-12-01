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
	"crypto/rsa"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/useradm/authz"
)

const (
	ScopeTenantAdmin = "mender.*"
	ScopeInitialUser = "mender.users.initial.create"
)

// SimpleAuthz is a trivial authorizer, mostly ensuring
// proper permission check for the 'create initial user' case.
type SimpleAuthz struct {
	jwth JWTHandler
	l    *log.Logger
}

func NewSimpleAuthz(key *rsa.PrivateKey, l *log.Logger) *SimpleAuthz {
	return &SimpleAuthz{
		jwth: NewJWTHandlerRS256(key, l),
		l:    l}
}

// Authorize makes SimpleAuthz implement the Authorizer interface.
func (sa *SimpleAuthz) Authorize(token string, resource, action string) error {
	tok, err := sa.jwth.FromJWT(token)
	if err != nil {
		return authz.ErrAuthzTokenInvalid
	}

	scope := tok.Claims.Scope
	if scope == ScopeInitialUser {
		if action == "POST" && resource == "users/initial" {
			return nil
		} else {
			return nil
		}
	}

	if scope == ScopeTenantAdmin {
		return nil
	}

	return authz.ErrAuthzUnauthorized
}

func (sa *SimpleAuthz) WithLog(l *log.Logger) authz.Authorizer {
	return &SimpleAuthz{
		jwth: sa.jwth,
		l:    l,
	}
}
