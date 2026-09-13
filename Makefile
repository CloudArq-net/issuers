.PHONY: build test drift clean

# issuers.json is generated from issuers.yaml. Both are committed: the YAML is the
# source of truth and carries the comments; the JSON is what the packages embed,
# so neither package needs a YAML parser at runtime.
build:
	@python3 scripts/build.py
	@cp issuers.json python/src/cloudarq_issuers/issuers.json
	@echo "built"

test: build
	@go test ./... && cd python && PYTHONPATH=src python3 -m pytest tests -q

# Re-fetch every discovery document and JWKS; exit non-zero on drift.
drift:
	@python3 scripts/drift.py

clean:
	@rm -f coverage.out
