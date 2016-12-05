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
	"encoding/json"
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/mendersoftware/go-lib-micro/log"
	"github.com/mendersoftware/go-lib-micro/requestlog"
	"github.com/mendersoftware/go-lib-micro/rest_utils"
	"github.com/mendersoftware/go-lib-micro/routing"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
)

const (
	uriAuthLogin    = "/api/0.1.0/auth/login"
	uriAuthVerify   = "/api/0.1.0/auth/verify"
	uriUsersInitial = "/api/0.1.0/users/initial"
)

var (
	ErrAuthHeader = errors.New("invalid or missing auth header")
)

type UserAdmFactory func(l *log.Logger) (UserAdmApp, error)

type UserAdmApiHandlers struct {
	createUserAdm UserAdmFactory
}

// return an ApiHandler for user administration and authentiacation app
func NewUserAdmApiHandlers(userAdmFactory UserAdmFactory) ApiHandler {
	return &UserAdmApiHandlers{
		createUserAdm: userAdmFactory,
	}
}

func (i *UserAdmApiHandlers) GetApp() (rest.App, error) {
	routes := []*rest.Route{
		rest.Post(uriAuthLogin, i.AuthLoginHandler),
		rest.Post(uriAuthVerify, i.AuthVerifyHandler),
		rest.Post(uriUsersInitial, i.PostUsersInitialHandler),
	}

	routes = append(routes)

	app, err := rest.MakeRouter(
		// augment routes with OPTIONS handler
		routing.AutogenOptionsRoutes(routes, routing.AllowHeaderOptionsGenerator)...,
	)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create router")
	}

	return app, nil
}

func (u *UserAdmApiHandlers) AuthLoginHandler(w rest.ResponseWriter, r *rest.Request) {
	l := requestlog.GetRequestLogger(r.Env)

	//parse auth header
	email, pass, ok := r.BasicAuth()
	if !ok && r.Header.Get("Authorization") != "" {
		rest_utils.RestErrWithLog(w, r, l,
			ErrAuthHeader, http.StatusUnauthorized)
		return
	}

	useradm, err := u.createUserAdm(l)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	// e.g. "useradm: unauthorized"; for now, every error is an internal one
	token, err := useradm.Login(email, pass)
	if err != nil {
		switch {
		case err == ErrUnauthorized:
			rest_utils.RestErrWithLog(w, r, l, err, http.StatusUnauthorized)
		default:
			rest_utils.RestErrWithLogInternal(w, r, l, err)
		}
		return
	}

	raw, err := token.MarshalJWT(useradm.SignToken())
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	w.(http.ResponseWriter).Write(raw)
	w.Header().Set("Content-Type", "application/jwt")
}

func (u *UserAdmApiHandlers) AuthVerifyHandler(w rest.ResponseWriter, r *rest.Request) {
	w.(http.ResponseWriter).WriteHeader(http.StatusOK)
}

func (u *UserAdmApiHandlers) PostUsersInitialHandler(w rest.ResponseWriter, r *rest.Request) {
	l := requestlog.GetRequestLogger(r.Env)

	// get and validate user from body
	var user UserModel
	body, err := readBodyRaw(r)
	if err != nil {
		err = errors.Wrap(err, "failed to decode user info")
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	err = json.Unmarshal(body, &user)
	if err != nil {
		err = errors.Wrap(err, "failed to decode user info")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	if err := user.ValidateNew(); err != nil {
		err = errors.Wrap(err, "invalid user info")
		rest_utils.RestErrWithLog(w, r, l, err, http.StatusBadRequest)
		return
	}

	useradm, err := u.createUserAdm(l)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	err = useradm.CreateUserInitial(&user)
	if err != nil {
		rest_utils.RestErrWithLogInternal(w, r, l, err)
		return
	}

	//TODO build URL
	w.Header().Set("Location", "TODO")
}

func readBodyRaw(r *rest.Request) ([]byte, error) {
	content, err := ioutil.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, err
	}

	return content, nil
}
