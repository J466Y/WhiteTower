module github.com/J466Y/WhiteTower/hack/spikes/s2

go 1.26.0

toolchain go1.27.2

require (
	connectrpc.com/connect v1.21.0
	github.com/J466Y/WhiteTower v0.0.0
	github.com/jackc/pgx/v5 v5.11.0
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace github.com/J466Y/WhiteTower => ../../..
