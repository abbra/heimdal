# Build the Rust PKINIT adapter static library.
# Called from Heimdal's build system when --enable-pkinit-rust is set.

CARGO ?= cargo
CARGO_FLAGS ?= --release
TARGET_DIR ?= target/release

.PHONY: all clean

all: $(TARGET_DIR)/libheimdal_pkinit.a

$(TARGET_DIR)/libheimdal_pkinit.a:
	$(CARGO) build $(CARGO_FLAGS)

clean:
	$(CARGO) clean
