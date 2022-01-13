/*
   Copyright 2021-2022 Nao Yonashiro

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

package fastcookiesession

import (
	"time"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/valyala/fasthttp"
)

func Get(store *sessions.CookieStore, ctx *fasthttp.RequestCtx, name string) (*sessions.Session, error) {
	sess := sessions.NewSession(store, name)
	opt := *store.Options
	sess.Options = &opt
	sess.IsNew = true

	c := ctx.Request.Header.Cookie(name)
	if len(c) > 0 {
		if securecookie.DecodeMulti(name, string(c), &sess.Values, store.Codecs...) == nil {
			sess.IsNew = false
		}
	}
	return sess, nil
}

func Save(store *sessions.CookieStore, ctx *fasthttp.RequestCtx, session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values, store.Codecs...)
	if err != nil {
		return err
	}
	opt := session.Options
	cookie := fasthttp.AcquireCookie()
	defer fasthttp.ReleaseCookie(cookie)
	cookie.SetDomain(opt.Domain)
	cookie.SetHTTPOnly(opt.HttpOnly)
	cookie.SetPath(opt.Path)
	cookie.SetSameSite(fasthttp.CookieSameSite(opt.SameSite))
	cookie.SetSecure(opt.Secure)
	cookie.SetMaxAge(opt.MaxAge)
	cookie.SetKey(session.Name())
	cookie.SetValue(encoded)
	if opt.MaxAge > 0 {
		cookie.SetExpire(time.Now().Add(time.Duration(opt.MaxAge) * time.Second))
	} else if opt.MaxAge < 0 {
		cookie.SetExpire(time.Unix(1, 0))
	}
	ctx.Response.Header.SetCookie(cookie)
	return nil
}
