.PHONY: build verify-vectors schema-check adversary test all clean

GO        ?= go
PYTHON    ?= python3
BUILD_DIR ?= build
VERIFIER  ?= $(BUILD_DIR)/aerf-verify
RENDERER  ?= $(BUILD_DIR)/aerf-render

build: $(VERIFIER) $(RENDERER)

$(VERIFIER):
	@mkdir -p $(BUILD_DIR)
	cd verifiers/go && $(GO) build -o $(CURDIR)/$(VERIFIER) ./cmd/aerf-verify

$(RENDERER):
	@mkdir -p $(BUILD_DIR)
	cd verifiers/go && $(GO) build -o $(CURDIR)/$(RENDERER) ./cmd/aerf-render

verify-vectors: build
	$(PYTHON) tools/run-vectors.py --verifier $(VERIFIER) --vectors vectors/

schema-check:
	$(PYTHON) tools/check-schemas.py

adversary: build
	@if ! $(PYTHON) -c "import aerf_adversary" >/dev/null 2>&1; then \
	  echo "==> installing aerf-adversary (editable)"; \
	  $(PYTHON) -m pip install -q -e tools/aerf-adversary; \
	fi
	$(PYTHON) -m aerf_adversary --verifier $(VERIFIER) --output $(BUILD_DIR)/adversary-report.json

test: verify-vectors schema-check adversary

all: test

clean:
	rm -rf $(BUILD_DIR)
