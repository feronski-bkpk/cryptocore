.PHONY: all build release test clean install test-all test-modes test-csprng test-auto-key test-weak-key test-nist test-nist-full test-nist-quick test-openssl test-comprehensive test-comprehensive-linux dev-test integration-test prepare-test clean-nist help test-hash test-hmac test-security test-performance test-aead test-gcm test-etm test-openssl-aead test-catastrophic-failure

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
	rm -f test.txt *.enc *.dec *.bin *.hmac *.sha256 *.sha3 *.gcm *.etm *.tag *.aad

install: release
	@echo "Installing cryptocore to /usr/local/bin/"
	cp target/release/cryptocore /usr/local/bin/cryptocore

# Полное тестирование всех компонентов
test-all: test-csprng test-auto-key test-weak-key test-modes test-openssl test-hash test-hmac test-aead
	@echo "All tests completed"

# Тестирование всех режимов шифрования
test-modes: test-ecb test-cbc test-cfb test-ofb test-ctr test-gcm test-etm
	@echo "All encryption mode tests completed"

# AEAD tests (GCM + ETM)
test-aead: test-gcm test-etm test-catastrophic-failure test-openssl-aead
	@echo "All AEAD tests completed"

# CSPRNG specific tests
test-csprng:
	@echo "Testing CSPRNG module..."
	cargo test --test csprng -- --nocapture

# Test automatic key generation
test-auto-key: prepare-test
	@echo "Testing automatic key generation..."
	# Encryption with auto key generation
	./target/release/cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
		--input test.txt \
		--output test.auto.enc
	@echo "Auto-key test completed. Check output for generated key."
	rm -f test.auto.enc

# Test weak key detection
test-weak-key: prepare-test
	@echo "Testing weak key detection..."
	# This should show a warning but still work
	@echo "Testing all zeros key (should show warning)..."
	./target/release/cryptocore crypto --algorithm aes --mode ecb --operation encrypt \
		--key 00000000000000000000000000000000 \
		--input test.txt \
		--output test.weak.enc 2>&1 | grep -q "WARNING" && echo "Weak key detection working" || echo "Weak key detection failed"
	# Sequential bytes should also trigger warning
	@echo "Testing sequential bytes key (should show warning)..."
	./target/release/cryptocore crypto --algorithm aes --mode ecb --operation encrypt \
		--key 000102030405060708090a0b0c0d0e0f \
		--input test.txt \
		--output test.weak2.enc 2>&1 | grep -q "WARNING" && echo "Sequential key detection working" || echo "Sequential key detection failed"
	rm -f test.weak.enc test.weak2.enc test.txt

# Hash function tests
test-hash: prepare-test
	@echo "Testing hash functions..."
	@echo "Testing SHA-256..."
	./target/release/cryptocore dgst --algorithm sha256 --input test.txt > test.sha256
	@cat test.sha256 | grep -q "da7e88e01cee7b2e" && echo "SHA-256: PASS" || echo "SHA-256: FAIL"

	@echo "Testing SHA3-256..."
	./target/release/cryptocore dgst --algorithm sha3-256 --input test.txt > test.sha3
	@cat test.sha3 | grep -q "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a" && echo "SHA3-256: PASS" || echo "SHA3-256: FAIL"

	@echo "Testing hash with output file..."
	./target/release/cryptocore dgst --algorithm sha256 --input test.txt --output test_output.sha256
	@test -f test_output.sha256 && echo "Hash output file: PASS" || echo "Hash output file: FAIL"

	rm -f test.sha256 test.sha3 test_output.sha256 test.txt
	@echo "Hash function tests completed"

# HMAC tests
test-hmac: prepare-test
	@echo "Testing HMAC functionality..."

	@echo "Testing HMAC generation..."
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt > test.hmac
	@cat test.hmac | grep -q ".* test.txt" && echo "HMAC generation: PASS" || echo "HMAC generation: FAIL"

	@echo "Testing HMAC verification..."
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt --verify test.hmac && echo "HMAC verification: PASS" || echo "HMAC verification: FAIL"

	@echo "Testing HMAC with different keys..."
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key aabbcc --input test.txt > test.hmac2
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key aabbcc --input test.txt --verify test.hmac2 && echo "HMAC different keys: PASS" || echo "HMAC different keys: FAIL"

	@echo "Testing HMAC tamper detection..."
	echo "tampered" >> test.txt
	./target/release/cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input test.txt --verify test.hmac 2>/dev/null && echo "HMAC tamper detection: FAIL" || echo "HMAC tamper detection: PASS"

	rm -f test.hmac test.hmac2 test.txt
	@echo "HMAC tests completed"

# GCM mode tests
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
	diff test.txt test.gcm.dec && echo "GCM with AAD: PASS" || echo "GCM with AAD: FAIL"

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
	diff test.txt test.gcm.auto.dec && echo "GCM auto nonce: PASS" || echo "GCM auto nonce: FAIL"

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
	diff test.txt test.gcm.empty.dec && echo "GCM empty AAD: PASS" || echo "GCM empty AAD: FAIL"

	rm -f test.gcm.* test.txt
	@echo "GCM tests completed"

# Encrypt-then-MAC tests
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
	diff test.txt test.etm.cbc.dec && echo "ETM-CBC: PASS" || echo "ETM-CBC: FAIL"

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
	diff test.txt test.etm.ctr.dec && echo "ETM-CTR: PASS" || echo "ETM-CTR: FAIL"

	rm -f test.etm.* test.txt
	@echo "ETM tests completed"

# Test catastrophic authentication failure (Sprint 6 requirement)
test-catastrophic-failure: prepare-test
	@echo "Testing catastrophic authentication failure..."

	@echo "Creating GCM encrypted file..."
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
		--key 00000000000000000000000000000000 \
		--nonce 000000000000000000000000 \
		--aad correctaad \
		--input test.txt \
		--output test.gcm.auth.enc

	@echo "Testing wrong AAD (should fail catastrophically)..."
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
		--key 00000000000000000000000000000000 \
		--aad wrongaad \
		--input test.gcm.auth.enc \
		--output test.gcm.wrong.dec 2>&1 | grep -q "Authentication failed" && echo "Catastrophic failure (wrong AAD): PASS" || echo "Catastrophic failure (wrong AAD): FAIL"
	# Verify no output file was created
	test ! -f test.gcm.wrong.dec && echo "No output file created on failure: PASS" || echo "No output file created on failure: FAIL"

	@echo "Testing wrong key (should fail)..."
	./target/release/cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
		--key ffffffffffffffffffffffffffffffff \
		--aad correctaad \
		--input test.gcm.auth.enc \
		--output test.gcm.wrongkey.dec 2>&1 | grep -q "Authentication failed" && echo "Catastrophic failure (wrong key): PASS" || echo "Catastrophic failure (wrong key): FAIL"

	rm -f test.gcm.* test.txt
	@echo "Catastrophic failure tests completed"

# NIST test data preparation
test-nist:
	@echo "Preparing NIST test data..."
	cargo test --test csprng test_nist_preparation -- --nocapture
	@echo "NIST test data generated: nist_test_data.bin"

# Full NIST STS testing (downloads and runs complete suite)
test-nist-full:
	@echo "Running full NIST STS testing..."
	@if [ -f "./scripts/test_nist.sh" ]; then \
		chmod +x ./scripts/test_nist.sh && \
		./scripts/test_nist.sh; \
	else \
		echo "NIST test script not found at ./scripts/test_nist.sh"; \
		echo "Try: make test-nist to generate test data only"; \
	fi

# Quick NIST validation (basic statistical tests)
test-nist-quick: test-nist
	@echo "⚡ Running quick NIST validation..."
	@cargo test --test csprng test_basic_distribution -- --nocapture
	@cargo test --test csprng test_key_uniqueness -- --nocapture
	@echo "Quick NIST validation completed"

# ECB mode (no IV)
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
	diff test.txt test.ecb.dec && echo "ECB: PASS" || echo "ECB: FAIL"
	rm -f test.ecb.enc test.ecb.dec test.txt

# CBC mode (with IV)
test-cbc: prepare-test
	@echo "Testing CBC mode..."
	# Encryption (auto-generates IV)
	./target/release/cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.cbc.enc
	# Decryption (extract IV from file)
	./target/release/cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.cbc.enc \
		--output test.cbc.dec
	diff test.txt test.cbc.dec && echo "CBC: PASS" || echo "CBC: FAIL"
	rm -f test.cbc.enc test.cbc.dec test.txt

# CFB mode (stream cipher)
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
	diff test.txt test.cfb.dec && echo "CFB: PASS" || echo "CFB: FAIL"
	rm -f test.cfb.enc test.cfb.dec test.txt

# OFB mode (stream cipher)
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
	diff test.txt test.ofb.dec && echo "OFB: PASS" || echo "OFB: FAIL"
	rm -f test.ofb.enc test.ofb.dec test.txt

# CTR mode (stream cipher)
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
	diff test.txt test.ctr.dec && echo "CTR: PASS" || echo "CTR: FAIL"
	rm -f test.ctr.enc test.ctr.dec test.txt

# Interoperability test with OpenSSL for classic modes
test-openssl: prepare-test
	@echo "Testing OpenSSL interoperability..."
	# Create test file
	echo "Hello OpenSSL Interop Test" > openssl_test.txt

	# Encrypt with OpenSSL, decrypt with our tool
	@if command -v openssl >/dev/null 2>&1; then \
		openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 000102030405060708090A0B0C0D0E0F -in openssl_test.txt -out openssl_encrypted.bin; \
		./target/release/cryptocore crypto --algorithm aes --mode cbc --operation decrypt \
			--key 00112233445566778899aabbccddeeff \
			--iv 000102030405060708090A0B0C0D0E0F \
			--input openssl_encrypted.bin \
			--output openssl_decrypted.txt; \
		diff openssl_test.txt openssl_decrypted.txt && echo "OpenSSL->OurTool: PASS" || echo "OpenSSL->OurTool: FAIL"; \
		\
		# Encrypt with our tool, decrypt with OpenSSL \
		./target/release/cryptocore crypto --algorithm aes --mode cbc --operation encrypt \
			--key 00112233445566778899aabbccddeeff \
			--input openssl_test.txt \
			--output our_encrypted.bin; \
		# Extract IV from our encrypted file \
		dd if=our_encrypted.bin of=extracted_iv.bin bs=16 count=1 2>/dev/null; \
		dd if=our_encrypted.bin of=ciphertext_only.bin bs=16 skip=1 2>/dev/null; \
		openssl enc -aes-128-cbc -d -K 00112233445566778899aabbccddeeff -iv $$(xxd -p extracted_iv.bin | tr -d '\n') -in ciphertext_only.bin -out openssl_decrypted2.txt; \
		diff openssl_test.txt openssl_decrypted2.txt && echo "OurTool->OpenSSL: PASS" || echo "OurTool->OpenSSL: FAIL"; \
		\
		# Cleanup \
		rm -f openssl_test.txt openssl_encrypted.bin openssl_decrypted.txt our_encrypted.bin extracted_iv.bin ciphertext_only.bin openssl_decrypted2.txt; \
	else \
		echo "OpenSSL not found, skipping interoperability tests"; \
	fi

# Interoperability test with OpenSSL for GCM
test-openssl-aead: prepare-test
	@echo "Testing OpenSSL GCM interoperability..."
	@if command -v openssl >/dev/null 2>&1; then \
		echo "Testing GCM interoperability with OpenSSL..."; \
		# Create test file \
		echo "GCM OpenSSL Interop Test" > gcm_openssl_test.txt; \
		\
		# Encrypt with OpenSSL GCM \
		echo "Encrypting with OpenSSL GCM..."; \
		openssl enc -aes-128-gcm -K 00000000000000000000000000000000 -iv 000000000000000000000000 -a -A -aad aabbccddeeff -in gcm_openssl_test.txt -out gcm_openssl_enc.bin 2>/dev/null; \
		if [ $$? -eq 0 ]; then \
			echo "OpenSSL GCM encryption successful"; \
			# Try to decrypt with our tool \
			./target/release/cryptocore crypto --algorithm aes --mode gcm --operation decrypt \
				--key 00000000000000000000000000000000 \
				--aad aabbccddeeff \
				--input gcm_openssl_enc.bin \
				--output gcm_our_decrypted.txt 2>&1; \
			if [ $$? -eq 0 ]; then \
				diff gcm_openssl_test.txt gcm_our_decrypted.txt && echo "OpenSSL GCM -> OurTool: PASS" || echo "OpenSSL GCM -> OurTool: FAIL (content mismatch)"; \
			else \
				echo "OpenSSL GCM -> OurTool: FAIL (decryption error)"; \
			fi; \
		else \
			echo "OpenSSL GCM encryption failed, skipping GCM interop test"; \
		fi; \
		\
		# Cleanup \
		rm -f gcm_openssl_test.txt gcm_openssl_enc.bin gcm_our_decrypted.txt 2>/dev/null || true; \
	else \
		echo "OpenSSL not found, skipping AEAD interoperability tests"; \
	fi

# Run comprehensive test scripts
test-comprehensive:
	@echo "Running comprehensive PowerShell tests..."
	@if [ -f "./scripts/test.ps1" ]; then \
		powershell -ExecutionPolicy Bypass -File scripts/test.ps1; \
	else \
		echo "PowerShell test script not found"; \
	fi

test-comprehensive-linux:
	@echo "Running comprehensive Linux tests..."
	@if [ -f "./scripts/test.sh" ]; then \
		chmod +x scripts/test.sh && \
		./scripts/test.sh; \
	else \
		echo "Linux test script not found"; \
	fi

# Prepare test file
prepare-test:
	@echo "Creating test file..."
	echo "This is a test file for CryptoCore encryption testing with various content patterns and data." > test.txt

# Clean NIST test data
clean-nist:
	@echo "Cleaning NIST test data..."
	rm -f nist_test_data.bin
	@if [ -d "./nist_sts" ]; then \
		rm -f nist_sts/nist_results.log nist_sts/finalAnalysisReport.txt nist_sts/assess_config.txt 2>/dev/null || true; \
		echo "NIST test data cleaned"; \
	fi

# Development quick test
dev-test: prepare-test test-csprng test-auto-key test-ecb test-cbc test-hash test-hmac test-gcm
	@echo "Development tests completed"
	rm -f test.txt

# Full integration test
integration-test: prepare-test test-all clean-nist
	@echo "Full integration tests completed"

# Quick build and test
quick: build test-comprehensive
	@echo "Quick build and test completed"

# Security-focused testing
test-security: test-csprng test-weak-key test-nist-quick test-hmac test-catastrophic-failure
	@echo "Security tests completed"

# Performance testing
test-performance: release
	@echo "Running performance tests..."
	@if [ -f "./scripts/test_perf.sh" ]; then \
		chmod +x scripts/test_perf.sh && \
		./scripts/test_perf.sh; \
	else \
		echo "Generating performance test data..."; \
		dd if=/dev/urandom of=perf_test_10mb.bin bs=1M count=10 2>/dev/null; \
		time ./target/release/cryptocore crypto --algorithm aes --mode ctr --operation encrypt \
			--key 00112233445566778899aabbccddeeff \
			--input perf_test_10mb.bin \
			--output perf_test_10mb.enc; \
		echo "Testing hash performance..."; \
		time ./target/release/cryptocore dgst --algorithm sha256 --input perf_test_10mb.bin; \
		echo "Testing HMAC performance..."; \
		time ./target/release/cryptocore dgst --algorithm sha256 --hmac --key 00112233445566778899aabbccddeeff --input perf_test_10mb.bin; \
		echo "Testing GCM performance..."; \
		time ./target/release/cryptocore crypto --algorithm aes --mode gcm --operation encrypt \
			--key 00112233445566778899aabbccddeeff \
			--aad "testaad" \
			--input perf_test_10mb.bin \
			--output perf_test_10mb.gcm.enc; \
		rm -f perf_test_10mb.bin perf_test_10mb.enc perf_test_10mb.gcm.enc; \
	fi

# RFC 4231 HMAC test vectors
test-hmac-rfc:
	@echo "Testing HMAC with RFC 4231 test vectors..."
	cargo test --test hmac -- --nocapture
	@echo "RFC 4231 HMAC tests completed"

# All hash-related tests
test-hash-all: test-hash test-hmac test-hmac-rfc
	@echo "All hash and HMAC tests completed"

# Unit tests for new modules
test-unit-aead:
	@echo "Running unit tests for AEAD modules..."
	cargo test --test aead -- --nocapture
	cargo test --test gcm -- --nocapture

# Validation tests for AEAD
test-validate-aead:
	@echo "Validating AEAD implementation..."
	@echo "Checking GCM implementation..."
	@if cargo test --test gcm 2>&1 | grep -q "test result: ok"; then \
		echo "GCM unit tests: PASS"; \
	else \
		echo "GCM unit tests: FAIL"; \
	fi
	@echo "Checking AEAD interface..."
	@if cargo test --test aead 2>&1 | grep -q "test result: ok"; then \
		echo "AEAD unit tests: PASS"; \
	else \
		echo "AEAD unit tests: FAIL"; \
	fi

# Help target
help:
	@echo "CryptoCore Makefile Targets:"
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
	@echo "  test-aead      - Test AEAD modes (GCM and ETM)"
	@echo "  test-gcm       - Test GCM mode"
	@echo "  test-etm       - Test Encrypt-then-MAC mode"
	@echo "  test-catastrophic-failure - Test authentication failure handling"
	@echo "  test-csprng    - Test CSPRNG module"
	@echo "  test-hash      - Test hash functions (SHA-256, SHA3-256)"
	@echo "  test-hmac      - Test HMAC functionality"
	@echo "  test-hmac-rfc  - Test HMAC with RFC 4231 vectors"
	@echo "  test-hash-all  - Test all hash and HMAC functionality"
	@echo "  test-nist      - Generate NIST test data"
	@echo "  test-nist-full - Run full NIST STS suite"
	@echo "  test-nist-quick- Quick NIST validation"
	@echo "  test-openssl   - Test OpenSSL interoperability (classic modes)"
	@echo "  test-openssl-aead - Test OpenSSL interoperability (GCM)"
	@echo "  test-security  - Run security-focused tests"
	@echo "  test-performance - Run performance tests"
	@echo "  test-unit-aead - Run unit tests for AEAD modules"
	@echo "  test-validate-aead - Validate AEAD implementation"
	@echo ""
	@echo "Development:"
	@echo "  dev-test       - Quick development tests"
	@echo "  integration-test - Full integration test"
	@echo "  quick          - Quick build and comprehensive test"
	@echo ""
	@echo "Comprehensive Testing:"
	@echo "  test-comprehensive     - Run PowerShell tests (Windows)"
	@echo "  test-comprehensive-linux - Run Linux shell tests"
	@echo ""
	@echo "Cleanup:"
	@echo "  clean-nist     - Clean NIST test data"
	@echo ""
	@echo "Sprint 6 Requirements Coverage:"
	@echo "  ✓ test-gcm - Tests GCM implementation (AEAD-2)"
	@echo "  ✓ test-etm - Tests Encrypt-then-MAC (AEAD-1)"
	@echo "  ✓ test-catastrophic-failure - Tests CLI-5 requirement"
	@echo "  ✓ test-openssl-aead - Tests TEST-8 requirement"
	@echo ""
	@echo "Example usage:"
	@echo "  make dev-test          # Quick development cycle"
	@echo "  make test-aead         # Test all AEAD functionality"
	@echo "  make test-security     # Security-focused testing"
	@echo "  make test-all          # Complete test suite"
	@echo "  make test-gcm          # Test GCM mode specifically"
	@echo "  make test-validate-aead # Validate AEAD implementation"