.PHONY: *

.SILENT:

default: help


# TODO: clean tools generate change_log
all:  start-local-kms hsmconfig build_all

help:
	@echo "Usage: make <target>"
	@echo "Targets:"
	@echo "  build    Build the project"
	@echo "  clean    Clean the project"
	@echo "  test     Run the tests"
	@echo "  help     Show this help message"

build_all:
	cd trusty-crypto11 && cargo build
	cd trusty-cryptoprov && cargo build --all-features
	# build for hsm-tool
	cd apps/hsm-tool && cargo build

hsmconfig:
	echo "*** Running hsmconfig"
	mkdir -p ~/softhsm2 /tmp/trusty11
	./scripts/config-softhsm.sh \
		--pin-file ~/softhsm2/trusty11_pin_unittest.txt \
		--generate-pin \
		-s trusty11_unittest \
		-o /tmp/trusty11/softhsm_unittest.json \
		--list-slots --list-object --delete
	echo ""

start-local-kms:
	echo "*** starting local-kms"
	docker compose -f docker-compose.yml -p trusty11-kms up -d --force-recreate --remove-orphans
