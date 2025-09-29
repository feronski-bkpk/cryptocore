.PHONY: all build release test clean install test-all test-modes

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

# Тестирование всех режимов
test-all: test-ecb test-cbc test-cfb test-ofb test-ctr

# ECB mode (no IV)
test-ecb:
	@echo "Testing ECB mode..."
	./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.ecb.enc
	./target/release/cryptocore --algorithm aes --mode ecb --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.ecb.enc \
		--output test.ecb.dec
	diff test.txt test.ecb.dec && echo "ECB: PASS" || echo "ECB: FAIL"
	rm -f test.ecb.enc test.ecb.dec

# CBC mode (with IV)
test-cbc:
	@echo "Testing CBC mode..."
	# Encryption (auto-generates IV)
	./target/release/cryptocore --algorithm aes --mode cbc --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.cbc.enc
	# Decryption (extract IV from file)
	./target/release/cryptocore --algorithm aes --mode cbc --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.cbc.enc \
		--output test.cbc.dec
	diff test.txt test.cbc.dec && echo "CBC: PASS" || echo "CBC: FAIL"
	rm -f test.cbc.enc test.cbc.dec

# CFB mode (stream cipher)
test-cfb:
	@echo "Testing CFB mode..."
	./target/release/cryptocore --algorithm aes --mode cfb --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.cfb.enc
	./target/release/cryptocore --algorithm aes --mode cfb --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.cfb.enc \
		--output test.cfb.dec
	diff test.txt test.cfb.dec && echo "CFB: PASS" || echo "CFB: FAIL"
	rm -f test.cfb.enc test.cfb.dec

# OFB mode (stream cipher)
test-ofb:
	@echo "Testing OFB mode..."
	./target/release/cryptocore --algorithm aes --mode ofb --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.ofb.enc
	./target/release/cryptocore --algorithm aes --mode ofb --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.ofb.enc \
		--output test.ofb.dec
	diff test.txt test.ofb.dec && echo "OFB: PASS" || echo "OFB: FAIL"
	rm -f test.ofb.enc test.ofb.dec

# CTR mode (stream cipher)
test-ctr:
	@echo "Testing CTR mode..."
	./target/release/cryptocore --algorithm aes --mode ctr --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.ctr.enc
	./target/release/cryptocore --algorithm aes --mode ctr --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.ctr.enc \
		--output test.ctr.dec
	diff test.txt test.ctr.dec && echo "CTR: PASS" || echo "CTR: FAIL"
	rm -f test.ctr.enc test.ctr.dec

# Interoperability test with OpenSSL
test-openssl:
	@echo "Testing OpenSSL interoperability..."
	# Create test file
	echo "Hello OpenSSL Interop Test" > openssl_test.txt

	# Encrypt with OpenSSL, decrypt with our tool
	openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 000102030405060708090A0B0C0D0E0F -in openssl_test.txt -out openssl_encrypted.bin
	./target/release/cryptocore --algorithm aes --mode cbc --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--iv 000102030405060708090A0B0C0D0E0F \
		--input openssl_encrypted.bin \
		--output openssl_decrypted.txt
	diff openssl_test.txt openssl_decrypted.txt && echo "OpenSSL->OurTool: PASS" || echo "OpenSSL->OurTool: FAIL"

	# Encrypt with our tool, decrypt with OpenSSL
	./target/release/cryptocore --algorithm aes --mode cbc --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input openssl_test.txt \
		--output our_encrypted.bin
	# Extract IV from our encrypted file
	dd if=our_encrypted.bin of=extracted_iv.bin bs=16 count=1 2>/dev/null
	dd if=our_encrypted.bin of=ciphertext_only.bin bs=16 skip=1 2>/dev/null
	openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -iv $(xxd -p extracted_iv.bin | tr -d '\n') -in ciphertext_only.bin -out openssl_decrypted2.txt
	diff openssl_test.txt openssl_decrypted2.txt && echo "OurTool->OpenSSL: PASS" || echo "OurTool->OpenSSL: FAIL"

	# Cleanup
	rm -f openssl_test.txt openssl_encrypted.bin openssl_decrypted.txt our_encrypted.bin extracted_iv.bin ciphertext_only.bin openssl_decrypted2.txt

# Prepare test file
prepare-test:
	echo "This is a test file for CryptoCore encryption testing." > test.txt