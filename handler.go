package authenticator

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	//	"math"
	//	"strconv"
	//	"fmt"
	"log"
	"net/http"
	//	"strconv"

	"os/user"
	"runtime"
	"strings"

	ctx "context"

	"github.com/alexbrainman/sspi"
	"github.com/alexbrainman/sspi/ntlm"
)

var (
	contexts    map[string]*ntlm.ServerContext
	serverCreds *sspi.Credentials
)

func init() {
	contexts = make(map[string]*ntlm.ServerContext)
	var err error
	serverCreds, err = ntlm.AcquireServerCredentials()
	if err != nil {
		panic(err)
	}
}

func initiateNTLM(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "NTLM")
	//	w.Header().Set("Connection", "Keep-Alive")
	//	w.Header().Set("Content-type", "text/xml")
	http.Error(w, "Authorization required", http.StatusUnauthorized)
	return
}

func authenticate(c *ntlm.ServerContext, authenticate []byte) (u *user.User, err error) {

	defer c.Release()
	err = c.Update(authenticate)

	if err != nil {

		return
	}

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	err = c.ImpersonateUser()
	if err != nil {
		return
	}

	defer c.RevertToSelf()

	u, err = user.Current()
	runtime.UnlockOSThread()

	return
}

func authenticate2(c *ntlm.ServerContext, authenticate []byte) (err error) {

	defer c.Release()
	err = c.Update(authenticate)

	return
}

func authorize(u *user.User, r *http.Request) bool {
	//	fmt.Println(u.Uid+" ("+u.Username+") wants ", r.URL.String())
	return true
}

func sendChallenge(negotiate []byte, w http.ResponseWriter, r *http.Request) {
	sc, ch, err := ntlm.NewServerContext(serverCreds, negotiate)
	if err != nil {
		http.Error(w, "NTLM error: "+err.Error(), http.StatusInternalServerError)
		return
	}
	contexts[r.RemoteAddr] = sc
	w.Header().Set("WWW-Authenticate", "NTLM "+base64.StdEncoding.EncodeToString(ch))
	http.Error(w, "Respond to challenge", http.StatusUnauthorized)
	return
}

// Authenticator authenticates the current request using NTLM
func Authenticator(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		var err error
		auth := r.Header.Get("Authorization")
		if auth == "" || (len(strings.SplitN(auth, " ", 2)) < 2) {
			initiateNTLM(w)
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		authType := parts[0]
		if authType != "NTLM" {
			initiateNTLM(w)
			return
		}
		var authPayload []byte
		authPayload, err = base64.StdEncoding.DecodeString(parts[1])
		context, ok := contexts[r.RemoteAddr]
		if !ok {
			sendChallenge(authPayload, w, r)
			return
		}
		defer delete(contexts, r.RemoteAddr)
		var u *user.User
		u, err = authenticate(context, authPayload)
		if err != nil {
			log.Println("auth error:", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if !authorize(u, r) {
			http.Error(w, u.Username+" is not authorized to do that", http.StatusUnauthorized)
		}
		w.Write([]byte("You are authenticated as " + u.Username + "\r\n"))
		next.ServeHTTP(w, r)
	}
	return http.HandlerFunc(fn)
}

func Authenticator2(next http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		if false && len(r.RequestURI) >= 3 && r.RequestURI[0:3] != "/g/" {
			next.ServeHTTP(w, r)
			return
		}
		var err error
		auth := r.Header.Get("Authorization")
		if auth == "" || (len(strings.SplitN(auth, " ", 2)) < 2) {
			initiateNTLM(w)
			return
		}
		parts := strings.SplitN(auth, " ", 2)
		authType := parts[0]
		if authType != "NTLM" {
			initiateNTLM(w)
			return
		}
		var authPayload []byte
		authPayload, err = base64.StdEncoding.DecodeString(parts[1])
		context, ok := contexts[r.RemoteAddr]
		if !ok {
			sendChallenge(authPayload, w, r)
			return
		}
		defer delete(contexts, r.RemoteAddr)

		err = authenticate2(context, authPayload)
		if err != nil {
			log.Println("auth error:", err)
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		userName := ""
		if authPayload[8] == 3 {

			var length int16
			binary.Read(bytes.NewReader([]byte{authPayload[36], authPayload[37]}), binary.LittleEndian, &length)
			//			log.Println(length)
			var offset int16
			binary.Read(bytes.NewReader([]byte{authPayload[40], authPayload[41]}), binary.LittleEndian, &offset)
			//			log.Println(offset)
			var buf []byte
			for i, v := range authPayload[offset : offset+length] {
				if i == ((i / 2) * 2) {
					buf = append(buf, v)
				}
			}

			userName = string(buf)
		}

		c := ctx.WithValue(r.Context(), "sso", userName)
		next.ServeHTTP(w, r.WithContext(c))
	}
	return http.HandlerFunc(fn)
}

/*

package main

import (
	"log"
	"net/http"

	"github.com/justinas/alice"
	"github.com/nycmonkey/authenticator"
)

func main() {
	mw := alice.New(authenticator.Authenticator)
	log.Println("starting service on :8080")
	log.Fatalln(http.ListenAndServe(":8080", mw.ThenFunc(getHandler)))
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("Success"))
	return
}

*/
