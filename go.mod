module mt-iam

go 1.16

replace github.com/minio/console => ../console

require (
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/dustin/go-humanize v1.0.0
	github.com/fsnotify/fsnotify v1.5.1
	github.com/go-ldap/ldap/v3 v3.4.2
	github.com/go-openapi/loads v0.20.2
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/gorilla/mux v1.8.0
	github.com/ipfs/go-ipfs-util v0.0.2
	github.com/json-iterator/go v1.1.12
	github.com/klauspost/compress v1.13.6
	github.com/klauspost/cpuid/v2 v2.0.9 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/lestrrat-go/jwx v1.2.14 // indirect
	github.com/lestrrat-go/strftime v1.0.5
	github.com/minio/console v0.9.8
	github.com/minio/highwayhash v1.0.2
	github.com/minio/kes v0.14.0
	github.com/minio/madmin-go v1.0.17
	github.com/minio/minio-go/v7 v7.0.13-0.20210715203016-9e713532886e
	github.com/minio/pkg v1.0.10
	github.com/minio/sha256-simd v1.0.0
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/common v0.32.1 // indirect
	github.com/rogpeppe/go-internal v1.8.1 // indirect
	github.com/rs/xid v1.3.0 // indirect
	github.com/shirou/gopsutil/v3 v3.21.12 // indirect
	github.com/spf13/viper v1.7.0
	github.com/tinylib/msgp v1.1.7-0.20211026165309-e818a1881b0e // indirect
	github.com/valyala/tcplisten v1.0.0
	go.opencensus.io v0.23.0
	go.uber.org/zap v1.16.1-0.20210329175301-c23abee72d19
	golang.org/x/crypto v0.0.0-20220128200615-198e4374d7ed // indirect
	golang.org/x/net v0.0.0-20220127200216-cd36cc0744dd // indirect
	golang.org/x/sys v0.0.0-20220128215802-99c3d69c2c27 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/ini.v1 v1.66.3 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gorm.io/driver/mysql v1.2.3
	gorm.io/gorm v1.22.5

)
