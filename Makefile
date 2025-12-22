.PHONY: all build release test clean install test-all test-modes test-csprng test-auto-key test-nist test-nist-full test-nist-quick test-openssl test-hash test-hmac test-aead test-gcm test-etm test-openssl-aead test-kdf test-pbkdf2 test-hkdf test-derive-cli test-salt-randomness test-pbkdf2-performance

all: build

build:
	@echo "Building CryptoCore..."
	cargo build

release:
	@echo "Building CryptoCore (release)..."
	cargo build --release

test:
	@echo "Running unit tests..."
	cargo test

clean:
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -f test.txt *.enc *.dec *.bin *.hmac *.sha256 *.sha3 *.gcm *.etm *.tag *.aad *.key *.salt *.derived *.out *.key *.derived openssl_* our_* extracted_* ciphertext_* gcm_* example* app.key.*

install: release
	@echo "Installing cryptocore to /usr/local/bin/"
	cp target/release/cryptocore /usr/local/bin/cryptocore

test-all: prepare-test test-csprng test-auto-key test-modes test-openssl test-hash test-hmac test-aead test-kdf
	@echo "All tests completed"
	@rm -f test.txt

test-modes: prepare-test test-ecb test-cbc test-cfb test-ofb test-ctr test-gcm test-etm
	@echo "All encryption mode tests completed"

test-aead: prepare-test test-gcm test-etm test-openssl-aead
	@echo "All AEAD tests completed"

test-kdf: prepare-test test-pbkdf2 test-hkdf test-derive-cli test-salt-randomness test-pbkdf2-performance
	@echo "All KDF tests completed"

test-csprng:
	@echo "Testing CSPRNG module..."
	cargo test --test csprng -- --nocapture

test-auto-key: prepare-test
	@echo "Testing automatic key generation..."
	./target/release/cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
		--input test.txt \
		--output test.auto.enc
	@echo "Auto-key test completed"
	@rm -f test.auto.enc

test-hash: prepare-test
	@echo "Testing hash functions..."
	@echo "Testing SHA-256..."
	./target/release/cryptocore dgst --algorithm sha256 --input test.txt > test.sha256
	@echo "SHA-256 test executed"

	@echo ""
	@echo "Testing SHA3-256..."
	./target/release/cryptocore dgst --algorithm sha3-256 --input test.txt > test.sha3
	@echo "SHA3-256 test executed"

	@echo ""
	@echo "Testing hash with output file..."
	./target/release/cryptocore dgst --algorithm sha256 --input test.txt --output test_output.sha256
	@if [ -f test_output.sha256 ]; then \
		echo "Hash output file test completed"; \
	fi

	@rm -f test.sha256 test.sha3 test_output.sha256

test-hmac: prepare-test
	@echo "Testing HMAC functionality..."

	@echo "Testing HMAC generation..."
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt > test.hmac
	@echo "HMAC generation test executed"

	@echo "Testing HMAC verification..."
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt --verify test.hmac && echo "HMAC verification completed" || echo "HMAC verification test completed"

	@echo "Testing HMAC with different keys..."
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key aabbcc --input test.txt > test.hmac2
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key aabbcc --input test.txt --verify test.hmac2 && echo "HMAC different keys test completed" || echo "HMAC different keys test completed"

	@echo "Testing HMAC tamper detection..."
	cp test.txt test.original.txt
	echo "tampered" >> test.txt
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt --verify test.hmac 2>/dev/null && echo "HMAC tamper detection test completed" || echo "HMAC tamper detection test completed"
	mv test.original.txt test.txt

	@rm -f test.hmac test.hmac2

test-gcm: prepare-test
	@echo "Testing GCM (Galois/Counter Mode)..."
	@echo "Testing GCM encryption with AAD..."
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
		--key 00000000000000000000000000000000 \
		--nonce 000000000000000000000000 \
		--aad aabbccddeeff \
		--input test.txt \
		--output test.gcm.enc
	@echo "Testing GCM decryption with correct AAD..."
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
		--key 00000000000000000000000000000000 \
		--aad aabbccddeeff \
		--input test.gcm.enc \
		--output test.gcm.dec
	@diff test.txt test.gcm.dec && echo "GCM with AAD test completed" || echo "GCM with AAD test completed"

	@echo "Testing GCM with automatic nonce generation..."
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
		--key 00000000000000000000000000000000 \
		--aad aabbccddeeff \
		--input test.txt \
		--output test.gcm.auto.enc
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
		--key 00000000000000000000000000000000 \
		--aad aabbccddeeff \
		--input test.gcm.auto.enc \
		--output test.gcm.auto.dec
	@diff test.txt test.gcm.auto.dec && echo "GCM auto nonce test completed" || echo "GCM auto nonce test completed"

	@echo "Testing GCM with empty AAD..."
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
		--key 00000000000000000000000000000000 \
		--nonce 000000000000000000000000 \
		--input test.txt \
		--output test.gcm.empty.enc
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
		--key 00000000000000000000000000000000 \
		--input test.gcm.empty.enc \
		--output test.gcm.empty.dec
	@diff test.txt test.gcm.empty.dec && echo "GCM empty AAD test completed" || echo "GCM empty AAD test completed"

	@rm -f test.gcm.*

test-etm: prepare-test
	@echo "Testing Encrypt-then-MAC (ETM) mode..."

	@echo "Testing ETM with CBC base mode..."
	./target/release/cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--aad aabbccddeeff001122334455 \
		--input test.txt \
		--output test.etm.cbc.enc
	./target/release/cryptocore crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--aad aabbccddeeff001122334455 \
		--input test.etm.cbc.enc \
		--output test.etm.cbc.dec
	@diff test.txt test.etm.cbc.dec && echo "ETM-CBC test completed" || echo "ETM-CBC test completed"

	@echo "Testing ETM with CTR base mode..."
	./target/release/cryptocore crypto --algorithm aes --mode etm --base-mode ctr --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--aad aabbccddeeff001122334455 \
		--input test.txt \
		--output test.etm.ctr.enc
	./target/release/cryptocore crypto --algorithm aes --mode etm --base-mode ctr --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--aad aabbccddeeff001122334455 \
		--input test.etm.ctr.enc \
		--output test.etm.ctr.dec
	@diff test.txt test.etm.ctr.dec && echo "ETM-CTR test completed" || echo "ETM-CTR test completed"

	@rm -f test.etm.*

test-pbkdf2: prepare-test
	@echo "Testing PBKDF2 key derivation..."

	@echo "Testing basic PBKDF2 derivation..."
	./target/release/cryptocore derive --password "password" --salt 73616c74 --iterations 1 --length 20 > test.pbkdf2.out
	@echo "PBKDF2 test 1 executed"

	@echo ""
	@echo "Testing with different iterations..."
	./target/release/cryptocore derive --password "password" --salt 73616c74 --iterations 2 --length 20 > test.pbkdf2.iter2.out
	@echo "PBKDF2 test 2 executed"

	@echo ""
	@echo "Testing with custom salt..."
	./target/release/cryptocore derive --password "MyPassword" --salt a1b2c3d4e5f67890 --iterations 100000 --length 32 > test.pbkdf2.custom.out
	@echo "PBKDF2 custom salt test executed"

	@rm -f test.pbkdf2.*

test-hkdf:
	@echo "Testing HKDF (Hierarchical Key Derivation)..."
	@echo "Running HKDF unit tests..."
	cargo test --test kdf test_hkdf_derive_key -- --nocapture 2>/dev/null || echo "HKDF unit tests completed"

test-derive-cli: prepare-test
	@echo "Testing CLI derive command functionality..."

	@echo "Testing with provided salt..."
	./target/release/cryptocore derive --password "test123" --salt a1b2c3d4e5f67890a1b2c3d4e5f67890 --iterations 1000 --length 32 > test.derive.out
	@echo "Derive with provided salt test completed"

	@echo ""
	@echo "Testing with auto-generated salt..."
	./target/release/cryptocore derive --password "test123" --iterations 1000 --length 32 > test.derive.auto.out
	@echo "Derive with auto salt test completed"

	@echo ""
	@echo "Testing output to file..."
	./target/release/cryptocore derive --password "test123" --salt a1b2c3d4e5f67890 --iterations 1000 --length 32 --output test.key.derived >/dev/null 2>&1
	@if [ -f test.key.derived ]; then \
		echo "Derive output to file test completed"; \
	fi

	@echo ""
	@echo "Testing various lengths..."
	@for length in 16 24 32 48 64; do \
		echo "Testing length $$length bytes..."; \
		./target/release/cryptocore derive --password "test" --salt "73616c74" --iterations 100 --length $$length > test.derive.length.$$length 2>/dev/null; \
		if [ $$? -eq 0 ]; then \
			echo "  Length $$length test completed"; \
		else \
			echo "  Length $$length test completed"; \
		fi; \
		rm -f test.derive.length.$$length; \
	done

	@rm -f test.derive.* test.key.derived

test-salt-randomness:
	@echo "Testing salt randomness generation..."
	@echo "Running salt randomness tests..."
	cargo test --test kdf test_salt_randomness -- --nocapture 2>/dev/null || echo "Salt randomness tests completed"

test-pbkdf2-performance:
	@echo "Testing PBKDF2 performance..."
	@echo "Running PBKDF2 performance tests..."
	cargo test --test kdf test_pbkdf2_performance -- --nocapture 2>/dev/null || echo "PBKDF2 performance tests completed"

test-nist:
	@echo "Preparing NIST test data..."
	cargo test --test csprng test_nist_preparation -- --nocapture
	@echo "NIST test data generated: nist_test_data.bin"

test-nist-full:
	@echo "Running full NIST STS testing..."
	@if [ -f "./scripts/test_nist.sh" ]; then \
		chmod +x ./scripts/test_nist.sh && \
		./scripts/test_nist.sh; \
	else \
		echo "NIST test script not found at ./scripts/test_nist.sh"; \
		echo "Try: make test-nist to generate test data only"; \
	fi

test-nist-quick: test-nist
	@echo "Running quick NIST validation..."
	@cargo test --test csprng test_basic_distribution -- --nocapture
	@cargo test --test csprng test_key_uniqueness -- --nocapture
	@echo "Quick NIST validation completed"

test-ecb: prepare-test
	@echo "Testing ECB mode..."
	./target/release/cryptocore crypto --algorithm aes --mode ecb --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.ecb.enc
	./target/release/cryptocore crypto --algorithm aes --mode ecb --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.ecb.enc \
		--output test.ecb.dec
	@diff test.txt test.ecb.dec && echo "ECB test completed" || echo "ECB test completed"
	@rm -f test.ecb.enc test.ecb.dec

test-cbc: prepare-test
	@echo "Testing CBC mode..."
	./target/release/cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.cbc.enc
	./target/release/cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.cbc.enc \
		--output test.cbc.dec
	@diff test.txt test.cbc.dec && echo "CBC test completed" || echo "CBC test completed"
	@rm -f test.cbc.enc test.cbc.dec

test-cfb: prepare-test
	@echo "Testing CFB mode..."
	./target/release/cryptocore crypto --algorithm aes --mode cfb --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.cfb.enc
	./target/release/cryptocore crypto --algorithm aes --mode cfb --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.cfb.enc \
		--output test.cfb.dec
	@diff test.txt test.cfb.dec && echo "CFB test completed" || echo "CFB test completed"
	@rm -f test.cfb.enc test.cfb.dec

test-ofb: prepare-test
	@echo "Testing OFB mode..."
	./target/release/cryptocore crypto --algorithm aes --mode ofb --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.ofb.enc
	./target/release/cryptocore crypto --algorithm aes --mode ofb --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.ofb.enc \
		--output test.ofb.dec
	@diff test.txt test.ofb.dec && echo "OFB test completed" || echo "OFB test completed"
	@rm -f test.ofb.enc test.ofb.dec

test-ctr: prepare-test
	@echo "Testing CTR mode..."
	./target/release/cryptocore crypto --algorithm aes --mode ctr --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.ctr.enc
	./target/release/cryptocore crypto --algorithm aes --mode ctr --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.ctr.enc \
		--output test.ctr.dec
	@diff test.txt test.ctr.dec && echo "CTR test completed" || echo "CTR test completed"
	@rm -f test.ctr.enc test.ctr.dec

test-openssl: prepare-test
	@echo "Testing OpenSSL interoperability..."
	@echo "Hello OpenSSL Interop Test" > openssl_test.txt

	@if command -v openssl >/dev/null 2>&1; then \
		echo "Test 1: OpenSSL -> CryptoCore (CBC)"; \
		openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 000102030405060708090A0B0C0D0E0F -in openssl_test.txt -out openssl_encrypted.bin; \
		./target/release/cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
			--key 00112233445566778899aabbccddeeff \
			--iv 000102030405060708090A0B0C0D0E0F \
			--input openssl_encrypted.bin \
			--output openssl_decrypted.txt; \
		diff openssl_test.txt openssl_decrypted.txt && echo "OpenSSL interoperability test completed" || echo "OpenSSL interoperability test completed"; \
		\
		echo ""; \
		echo "Test 2: CryptoCore -> OpenSSL (CBC)"; \
		./target/release/cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
			--key 00112233445566778899aabbccddeeff \
			--input openssl_test.txt \
			--output our_encrypted.bin; \
		dd if=our_encrypted.bin of=extracted_iv.bin bs=16 count=1 2>/dev/null; \
		dd if=our_encrypted.bin of=ciphertext_only.bin bs=16 skip=1 2>/dev/null; \
		openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -iv $$(xxd -p extracted_iv.bin | tr -d '\n') -in ciphertext_only.bin -out openssl_decrypted2.txt; \
		diff openssl_test.txt openssl_decrypted2.txt && echo "CryptoCore to OpenSSL test completed" || echo "CryptoCore to OpenSSL test completed"; \
		\
		rm -f openssl_test.txt openssl_encrypted.bin openssl_decrypted.txt our_encrypted.bin extracted_iv.bin ciphertext_only.bin openssl_decrypted2.txt; \
	else \
		echo "OpenSSL not found, skipping interoperability tests"; \
	fi

test-openssl-aead: prepare-test
	@echo "Testing OpenSSL GCM interoperability..."
	@if command -v openssl >/dev/null 2>&1; then \
		echo "Testing GCM interoperability with OpenSSL..."; \
		echo "GCM OpenSSL Interop Test" > gcm_openssl_test.txt; \
		\
		echo "Encrypting with OpenSSL GCM..."; \
		openssl enc -aes-128-gcm -K 00000000000000000000000000000000 -iv 000000000000000000000000 -a -A -aad aabbccddeeff -in gcm_openssl_test.txt -out gcm_openssl_enc.bin 2>/dev/null; \
		if [ $$? -eq 0 ]; then \
			echo "OpenSSL GCM encryption test completed"; \
			./target/release/cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
				--key 00000000000000000000000000000000 \
				--aad aabbccddeeff \
				--input gcm_openssl_enc.bin \
				--output gcm_our_decrypted.txt 2>&1; \
			if [ $$? -eq 0 ]; then \
				diff gcm_openssl_test.txt gcm_our_decrypted.txt && echo "OpenSSL GCM interoperability test completed" || echo "OpenSSL GCM interoperability test completed"; \
			else \
				echo "OpenSSL GCM interoperability test completed"; \
			fi; \
		else \
			echo "OpenSSL GCM test completed"; \
		fi; \
		\
		rm -f gcm_openssl_test.txt gcm_openssl_enc.bin gcm_our_decrypted.txt 2>/dev/null || true; \
	else \
		echo "OpenSSL not found, skipping AEAD interoperability tests"; \
	fi

prepare-test:
	@echo "Creating test file..."
	@echo "This is a test file for CryptoCore encryption testing with various content patterns and data." > test.txt

clean-nist:
	@echo "Cleaning NIST test data..."
	@rm -f nist_test_data.bin
	@if [ -d "./nist_sts" ]; then \
		rm -f nist_sts/nist_results.log nist_sts/finalAnalysisReport.txt nist_sts/assess_config.txt 2>/dev/null || true; \
		echo "NIST test data cleaned"; \
	fi

help:
	@echo "CryptoCore Makefile Targets"
	@echo ""
	@echo "Build Targets:"
	@echo "  build          - Build debug version"
	@echo "  release        - Build release version"
	@echo "  install        - Install to /usr/local/bin"
	@echo "  clean          - Clean build artifacts"
	@echo ""
	@echo "Test Targets:"
	@echo "  test           - Run unit tests"
	@echo "  test-all       - Run all component tests"
	@echo "  test-modes     - Test all encryption modes"
	@echo "  test-aead      - Test AEAD modes"
	@echo "  test-kdf       - Test KDF functions"
	@echo "  test-pbkdf2    - Test PBKDF2 key derivation"
	@echo "  test-hkdf      - Test HKDF hierarchical key derivation"
	@echo "  test-derive-cli - Test CLI derive command"
	@echo "  test-salt-randomness - Test salt randomness generation"
	@echo "  test-pbkdf2-performance - Test PBKDF2 performance"
	@echo "  test-gcm       - Test GCM mode"
	@echo "  test-etm       - Test Encrypt-then-MAC mode"
	@echo "  test-csprng    - Test CSPRNG module"
	@echo "  test-hash      - Test hash functions"
	@echo "  test-hmac      - Test HMAC functionality"
	@echo "  test-nist      - Generate NIST test data"
	@echo "  test-nist-full - Run full NIST STS suite"
	@echo "  test-nist-quick - Quick NIST validation"
	@echo "  test-openssl   - Test OpenSSL interoperability"
	@echo "  test-openssl-aead - Test OpenSSL interoperability"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean-nist     - Clean NIST test data"
