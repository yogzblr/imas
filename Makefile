UNAME:=$(shell uname|sed 's/.*/\u&/')
OS:=$(shell echo $(GOOS)| sed 's/.*/\u&/')
PKG=$(shell basename $$(pwd))
colon := :
ifeq  ($(BITBUCKET_BUILD_NUMBER),)
TYPE:="Local"
else
TYPE:=$(BITBUCKET_BUILD_NUMBER)
endif


all:  sprout imas farmer

sprout: cmd/sprout/*.go
ifeq ($(GOOS),)
	@printf "OS not specified, defaulting to: \e[33m$(UNAME)\e[39m\n"
else
	@printf "OS specified: \e[33m$$(echo $$GOOS | sed 's/.*/\u&/' )\e[39m\n"
endif
	@echo "Building..."
	@export GOARCH=amd64; \
	export BITBUCKET_BUILD_NUMBER=$(TYPE);\
	export CGO_ENABLED=0;\
	export GitCommit=`git rev-parse HEAD | cut -c -7`;\
	export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
	go build -ldflags "-X main.GitCommit=$$GitCommit -X main.Tag=$$GitTag" -o "bin/imas-sprout" ./cmd/sprout/*.go
	@printf "\e[32mSuccess!\e[39m\n"


imas: cmd/imas/*.go
ifeq ($(GOOS),)
	@printf "OS not specified, defaulting to: \e[33m$(UNAME)\e[39m\n"
else
	@printf "OS specified: \e[33m$$(echo $$GOOS | sed 's/.*/\u&/' )\e[39m\n"
endif
	@echo "Building..."
	@export GOARCH=amd64; \
	export BITBUCKET_BUILD_NUMBER=$(TYPE);\
	export CGO_ENABLED=0;\
	export GitCommit=`git rev-parse HEAD | cut -c -7`;\
	export BuildTime=`date -u +%Y%m%d.%H%M%S`;\
	export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
	go build -ldflags "-X main.GitCommit=$$GitCommit -X main.Tag=$$GitTag" -o "bin/imas" ./cmd/imas/main.go
	@printf "\e[32mSuccess!\e[39m\n"


farmer: cmd/farmer/*.go
ifeq ($(GOOS),)
	@printf "OS not specified, defaulting to: \e[33m$(UNAME)\e[39m\n"
else
	@printf "OS specified: \e[33m$$(echo $$GOOS | sed 's/.*/\u&/' )\e[39m\n"
endif
	@echo "Building..."
	@export GOARCH=amd64; \
	export BITBUCKET_BUILD_NUMBER=$(TYPE);\
	export CGO_ENABLED=0;\
	export GitCommit=`git rev-parse HEAD | cut -c -7`;\
	export BuildTime=`date -u +%Y%m%d.%H%M%S`;\
	export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
	go build -ldflags "-X main.GitCommit=$$GitCommit -X main.Tag=$$GitTag" -o "bin/imas-farmer" ./cmd/farmer/main.go
	@printf "\e[32mSuccess!\e[39m\n"

all-arches-farmer: farmer
	@mkdir -p bin/arches
	for arch in amd64 386 arm arm64 ; do \
		export GOOS=linux; \
		export GOARCH=$$arch; \
		export BITBUCKET_BUILD_NUMBER=$(TYPE);\
		export CGO_ENABLED=0;\
		export GitCommit=`git rev-parse HEAD | cut -c -7`;\
		export BuildTime=`date -u +%Y%m%d.%H%M%S`;\
		export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
		go build -ldflags "-X main.GitCommit=$$GitCommit -X main.Tag=$$GitTag" -o "bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/"$$(printf $$GitTag)"/imas-farmer" ./cmd/farmer/main.go &&\
		printf "\e[32mSuccess!\e[39m\n" ;\
		mkdir -p bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/latest ;\
		cp bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/"$$(printf $$GitTag)"/imas-farmer bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/latest/imas-farmer ;\
	done

all-arches-sprout: sprout
	@mkdir -p bin/arches
	for arch in amd64 386 arm arm64 ; do \
		export GOOS=linux; \
		export GOARCH=$$arch; \
		export BITBUCKET_BUILD_NUMBER=$(TYPE);\
		export CGO_ENABLED=0;\
		export GitCommit=`git rev-parse HEAD | cut -c -7`;\
		export BuildTime=`date -u +%Y%m%d.%H%M%S`;\
		export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
		go build -ldflags "-X main.GitCommit=$$GitCommit -X main.Tag=$$GitTag" -o "bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/"$$(printf $$GitTag)"/imas-sprout" ./cmd/sprout/*.go &&\
		printf "\e[32mSuccess!\e[39m\n" ;\
		mkdir -p bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/latest ;\
		cp bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/"$$(printf $$GitTag)"/imas-sprout bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/latest/imas-sprout ;\
	done

all-arches-imas: imas
	@mkdir -p bin/arches
	for arch in amd64 386 arm arm64 ; do \
			export GOOS=linux; \
			export GOARCH=$$arch; \
			export BITBUCKET_BUILD_NUMBER=$(TYPE);\
			export CGO_ENABLED=0;\
			export GitCommit=`git rev-parse HEAD | cut -c -7`;\
			export BuildTime=`date -u +%Y%m%d.%H%M%S`;\
			export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
			go build -ldflags "-X main.GitCommit=$$GitCommit -X main.Tag=$$GitTag" -o "bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/"$$(printf $$GitTag)"/imas" ./cmd/imas/main.go &&\
			printf "\e[32mSuccess!\e[39m\n" ;\
			mkdir -p bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/latest ;\
			cp bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/"$$(printf $$GitTag)"/imas bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/latest/imas ;\
	done
	for arch in amd64 arm64 ; do \
			export GOOS=darwin; \
			export GOARCH=$$arch; \
			export BITBUCKET_BUILD_NUMBER=$(TYPE);\
			export CGO_ENABLED=0;\
			export GitCommit=`git rev-parse HEAD | cut -c -7`;\
			export BuildTime=`date -u +%Y%m%d.%H%M%S`;\
			export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
			go build -ldflags "-X main.GitCommit=$$GitCommit -X main.Tag=$$GitTag" -o "bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/"$$(printf $$GitTag)"/imas" ./cmd/imas/main.go &&\
			printf "\e[32mSuccess!\e[39m\n" ;\
			mkdir -p bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/latest ;\
			cp bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/"$$(printf $$GitTag)"/imas bin/arches/"$$(printf $$GOOS)"/"$$(printf $$GOARCH)"/latest/imas ;\
	done

github: all-arches-farmer all-arches-sprout all-arches-imas
	@printf "Creating GitHub release...\n"
	mkdir -p bin/github
	for arch in amd64 386 arm arm64 ; do \
		export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
		cp bin/arches/linux/$$arch/$$(printf $$GitTag)/imas-farmer bin/github/imas-farmer-$$(printf $$GitTag)-linux-$$(printf $$arch);\
		tar -czf bin/github/imas-farmer-$$(printf $$GitTag)-linux-$$(printf $$arch).tar.gz \
	      -C bin/arches/linux/$$arch/$$(printf $$GitTag) imas-farmer;\
	done
	for arch in amd64 386 arm arm64 ; do \
		export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
		cp bin/arches/linux/$$arch/$$(printf $$GitTag)/imas-sprout bin/github/imas-sprout-$$(printf $$GitTag)-linux-$$(printf $$arch);\
		tar -czf bin/github/imas-sprout-$$(printf $$GitTag)-linux-$$(printf $$arch).tar.gz \
			-C bin/arches/linux/$$arch/$$(printf $$GitTag) imas-sprout;\
	done
	for arch in amd64 arm64 ; do \
		export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
		cp bin/arches/darwin/$$arch/$$(printf $$GitTag)/imas bin/github/imas-$$(printf $$GitTag)-darwin-$$(printf $$arch);\
		tar -czf bin/github/imas-$$(printf $$GitTag)-darwin-$$(printf $$arch).tar.gz \
			-C bin/arches/darwin/$$arch/$$(printf $$GitTag) imas;\
	done
	for arch in amd64 386 arm arm64 ; do \
		export GitTag=$$(TAG=`git tag --contains $$(git rev-parse HEAD) | sort -R | tr '\n' ' '`; if [ "$$(printf "$$TAG")" ]; then printf "$$TAG"; else printf "undefined"; fi);\
		cp bin/arches/linux/$$arch/$$(printf $$GitTag)/imas bin/github/imas-$$(printf $$GitTag)-linux-$$(printf $$arch);\
		tar -czf bin/github/imas-$$(printf $$GitTag)-linux-$$(printf $$arch).tar.gz \
			-C bin/arches/linux/$$arch/$$(printf $$GitTag) imas;\
	done
	
release: all-arches-farmer all-arches-sprout all-arches-imas github
	@printf "\e[32mSuccess!\e[39m\n"



clean:
	@printf "Cleaning up \e[32mmain\e[39m...\n"
	docker-compose down || true
	yes| docker-compose rm || true
	docker rmi imas/sprout:latest || true
	docker rmi imas/farmer:latest || true
	rm -f ~/.config/imas/tls-rootca.pem
	rm -f main bin/imas bin/imas-farmer bin/imas-sprout
	rm -r bin/arches bin/github || true

install: clean all
	mv bin/imas bin/imas-farmer bin/imas-sprout "$$GOPATH/bin/"

docker:
	docker build -t imas/farmer . -f docker/farmer.dockerfile
	docker build -t imas/sprout . -f docker/sprout.dockerfile

dcu:
	docker-compose down || true
	docker-compose rm
	rm -f ~/.config/imas/tls-rootca.pem
	docker-compose up

test: clean
	docker-compose build
	docker-compose up -d
	@printf "\e[31mNo tests defined!\e[39m\n"
	docker compose down
	@exit 1

# gendocs regenerates docs-site/src/ingredients/*.md from internal/ingredients/
# (see tools/gendocs) -- it's a separate Go module so it never needs this
# repo's go.mod toolchain version. Those generated files are gitignored;
# `make docs` (needs mdbook: https://rust-lang.github.io/mdBook/guide/installation.html)
# regenerates them and builds the site into docs-site/book/.
gendocs:
	cd tools/gendocs && go run . -src ../../internal/ingredients -out ../../docs-site/src/ingredients

docs: gendocs
	mdbook build docs-site

docs-serve: gendocs
	mdbook serve docs-site --open

.PHONY: gendocs
.PHONY: docs
.PHONY: docs-serve
.PHONY: all
.PHONY: clean
.PHONY: docker
.PHONY: install
.PHONY: test
.PHONY: update
.PHONY: release
