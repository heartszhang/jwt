package main

import (
	"encoding/hex"
	"fmt"
	"net/http"
)

func main() {
	http.HandleFunc("/xsts", http_xsts)
	http.HandleFunc("/a128", http_bestvdrm_key)
	http.HandleFunc("/xkey", http_xext_key)
	http.ListenAndServe(":5000", nil)
}
func main_xsts() {
	xt, err := create_xsts_token("023513000031081") //hearts.zhang@outlook.com
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(xt)
}
func http_xsts(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var uid string
	if uid = r.FormValue("uid"); uid == "" {
		uid = "023513000031081"
	}
	w.Header().Set("Content-Type", "text/plain")

	if xt, err := create_xsts_token(uid); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	} else {
		w.Write([]byte(xt))
	}

}

func http_bestvdrm_key(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Content-Type", "text/plain")
	var uri = r.FormValue("uri")
	if uri == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bestvdrm://hdnba1/20150516/"))
		return
	}
	if key, err := bestvdrm_to_a128key(uri); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	} else {
		w.Write([]byte(hex.EncodeToString(key)))
	}
}

func http_xext_key(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	w.Header().Set("Content-Type", "text/plain")
	var ext = r.FormValue("ext")
	if ext == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`METHOD=AES-128,URI="bestvdrm://hdnba1/20150516/"`))
		return
	}
	if key, err := x_ext_to_a128key(ext); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	} else {
		w.Write([]byte(hex.EncodeToString(key)))
	}
}
