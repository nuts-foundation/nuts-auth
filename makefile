.PHONY: run-generators update-nuts-deps update-docs test

run-generators:
	go-bindata -ignore=\\.DS_Store -pkg=assets -o=./assets/bindata.go -prefix=bindata ./bindata/...
	oapi-codegen -generate server,types -package v0 docs/_static/nuts-auth.yaml > api/v0/generated.go
	oapi-codegen -generate server,types -package experimental docs/_static/nuts-auth-experimental.yaml > api/experimental/generated.go
	mockgen -destination=mock/mock_auth_client.go -package=mock_auth -source=pkg/auth.go
	mockgen -destination=mock/services/mock.go -package=mock_services -source=pkg/services/services.go
	mockgen -destination=mock/contract/signer_mock.go -source=pkg/contract/signer.go

update-nuts-deps:
	cat go.mod | awk '/nuts-foundation.* / {print $$1 "@master"}' | xargs go get

test:
	go test ./...

update-docs:
	go run ./docs
	./generate_readme.sh
