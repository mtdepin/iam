module mt-iam

go 1.16

require github.com/gin-gonic/gin v1.7.7

require (
	github.com/dustin/go-humanize v1.0.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/go-ldap/ldap/v3 v3.4.2
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/ipfs/go-ipfs-util v0.0.2
	github.com/json-iterator/go v1.1.12
	github.com/klauspost/compress v1.13.6
	github.com/minio/highwayhash v1.0.2
	github.com/minio/kes v0.17.6
	github.com/minio/madmin-go v1.3.4
	github.com/minio/minio v0.0.0-20220225011753-890e526bdee8
	github.com/minio/minio-go/v7 v7.0.23
	github.com/minio/pkg v1.1.16
	github.com/minio/selfupdate v0.4.0
	github.com/minio/sha256-simd v1.0.0
	github.com/prometheus/client_golang v1.11.0
	github.com/secure-io/sio-go v0.3.1
	github.com/spf13/viper v1.9.0
	github.com/valyala/tcplisten v1.0.0
	go.opencensus.io v0.23.0
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gorm.io/driver/mysql v1.2.3
	gorm.io/gorm v1.22.5
)
