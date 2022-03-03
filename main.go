package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	config "mt-iam/conf"
	"mt-iam/datastore"
	"mt-iam/internal"
	xhttp "mt-iam/internal/http"
	"net/http"
	"strings"
)

func main() {
	fmt.Println("server start")
	config.InitConfig()
	datastore.InitDB()
	internal.Start()
	// Initialize router. `SkipClean(true)` stops gorilla/mux from
	// normalizing URL path minio/minio#3256
	// avoid URL path encoding minio/minio#8950
	router := mux.NewRouter().SkipClean(true).UseEncodedPath()
	addr := ":10001"

	// Enable STS router if etcd is enabled.
	internal.RegisterAdminRouter(router)
	internal.RegisterSTSRouter(router)

	//包装的handler，处理定义之外的请求
	wrappedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 拦截 RequestURI 前缀 为 "/claim" 的请求
		if strings.Contains(r.RequestURI, "/claim") {
			//把前缀去掉
			r.RequestURI = strings.Replace(r.RequestURI, "/claim", "", 1)
			token := internal.MustGetClaimsFromToken(r)
			// todo 处理异常结果返回
			if token != nil {
				//写入返回结果
				w.Header().Set(xhttp.ContentType, "content-type/json")
				w.WriteHeader(200)
				result, _ := json.Marshal(token)
				_, _ = w.Write(result)
				w.(http.Flusher).Flush()
				return
			}
			w.Header().Set(xhttp.ContentType, "content-type/json")
			w.WriteHeader(200)
			_, _ = w.Write([]byte(""))
			w.(http.Flusher).Flush()
			return
		} else if strings.Contains(r.RequestURI, "/auth") {
			r.RequestURI = strings.Replace(r.RequestURI, "/auth", "", 1)
			r.URL.Path = strings.Replace(r.URL.Path, "/auth", "", 1)

			//r.Host = "192.168.1.135:9000"
			internal.IsAllowed(w, r)
			return
		} else if strings.Contains(r.RequestURI, "/validateSignature") {
			r.RequestURI = strings.Replace(r.RequestURI, "/validateSignature", "", 1)
			r.URL.Path = strings.Replace(r.URL.Path, "/validateSignature", "", 1)

			internal.IsAllowed(w, r)
			return
		}
		// Handle request using passed handler.
		//正常请求
		router.ServeHTTP(w, r)
	})

	sever := xhttp.NewServer([]string{addr}, wrappedHandler, nil)
	//go func() {
	//	sever.Start()
	//}()
	//api.InitRouter()

	sever.Start()
}
