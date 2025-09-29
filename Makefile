.PHONY: all build release test clean install

all: build

build:
	cargo build

release:
	cargo build --release

test:
	cargo test

clean:
	cargo clean

install: release
	cp target/release/cryptocore /usr/local/bin/cryptocore

# Тестовые команды
test-encrypt:
	./target/release/cryptocore -algorithm aes -mode ecb -encrypt \
		-key 00112233445566778899aabbccddeeff \
		-input test.txt \
		-output test.enc

test-decrypt:
	./target/release/cryptocore -algorithm aes -mode ecb -decrypt \
		-key 00112233445566778899aabbccddeeff \
		-input test.enc \
		-output test.dec