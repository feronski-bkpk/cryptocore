.PHONY: all build release test clean install test-all test-modes test-csprng test-auto-key test-weak-key test-nist test-nist-full test-nist-quick test-openssl test-comprehensive test-comprehensive-linux dev-test integration-test prepare-test clean-nist help

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
	rm -f test.txt *.enc *.dec *.bin

install: release
	@echo "Installing cryptocore to /usr/local/bin/"
	cp target/release/cryptocore /usr/local/bin/cryptocore

# Полное тестирование всех компонентов
test-all: test-csprng test-auto-key test-weak-key test-modes test-openssl
	@echo "All tests completed"

# Тестирование всех режимов шифрования
test-modes: test-ecb test-cbc test-cfb test-ofb test-ctr
	@echo "All encryption mode tests completed"

# CSPRNG specific tests
test-csprng:
	@echo "Testing CSPRNG module..."
	cargo test --test csprng -- --nocapture

# Test automatic key generation
test-auto-key: prepare-test
	@echo "Testing automatic key generation..."
	# Encryption with auto key generation
	./target/release/cryptocore --algorithm aes --mode cbc --operation encrypt \
		--input test.txt \
		--output test.auto.enc
	@echo "Auto-key test completed. Check output for generated key."
	rm -f test.auto.enc

# Test weak key detection
test-weak-key: prepare-test
	@echo "Testing weak key detection..."
	# This should show a warning but still work
	@echo "Testing all zeros key (should show warning)..."
	./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt \
		--key 00000000000000000000000000000000 \
		--input test.txt \
		--output test.weak.enc 2>&1 | grep -q "WARNING" && echo "Weak key detection working" || echo "Weak key detection failed"
	# Sequential bytes should also trigger warning
	@echo "Testing sequential bytes key (should show warning)..."
	./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt \
		--key 000102030405060708090a0b0c0d0e0f \
		--input test.txt \
		--output test.weak2.enc 2>&1 | grep -q "WARNING" && echo "Sequential key detection working" || echo "Sequential key detection failed"
	rm -f test.weak.enc test.weak2.enc test.txt

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
	./target/release/cryptocore --algorithm aes --mode ecb --operation encrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.txt \
		--output test.ecb.enc
	./target/release/cryptocore --algorithm aes --mode ecb --operation decrypt \
		--key 00112233445566778899aabbccddeeff \
		--input test.ecb.enc \
		--output test.ecb.dec
	diff test.txt test.ecb.dec && echo "ECB: PASS" || echo "ECB: FAIL"
	rm -f test.ecb.enc test.ecb.dec test.txt

# CBC mode (with IV)
test-cbc: prepare-test
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
	rm -f test.cbc.enc test.cbc.dec test.txt

# CFB mode (stream cipher)
test-cfb: prepare-test
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
	rm -f test.cfb.enc test.cfb.dec test.txt

# OFB mode (stream cipher)
test-ofb: prepare-test
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
	rm -f test.ofb.enc test.ofb.dec test.txt

# CTR mode (stream cipher)
test-ctr: prepare-test
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
	rm -f test.ctr.enc test.ctr.dec test.txt

# Interoperability test with OpenSSL
test-openssl: prepare-test
	@echo "Testing OpenSSL interoperability..."
	# Create test file
	echo "Hello OpenSSL Interop Test" > openssl_test.txt

	# Encrypt with OpenSSL, decrypt with our tool
	@if command -v openssl >/dev/null 2>&1; then \
		openssl enc -aes-128-cbc -K 00112233445566778899aabbccddeeff -iv 000102030405060708090A0B0C0D0E0F -in openssl_test.txt -out openssl_encrypted.bin; \
		./target/release/cryptocore --algorithm aes --mode cbc --operation decrypt \
			--key 00112233445566778899aabbccddeeff \
			--iv 000102030405060708090A0B0C0D0E0F \
			--input openssl_encrypted.bin \
			--output openssl_decrypted.txt; \
		diff openssl_test.txt openssl_decrypted.txt && echo "OpenSSL->OurTool: PASS" || echo "OpenSSL->OurTool: FAIL"; \
		\
		# Encrypt with our tool, decrypt with OpenSSL \
		./target/release/cryptocore --algorithm aes --mode cbc --operation encrypt \
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
dev-test: prepare-test test-csprng test-auto-key test-ecb test-cbc
	@echo "Development tests completed"
	rm -f test.txt

# Full integration test
integration-test: prepare-test test-all clean-nist
	@echo "Full integration tests completed"

# Quick build and test
quick: build test-comprehensive
	@echo "Quick build and test completed"

# Security-focused testing
test-security: test-csprng test-weak-key test-nist-quick
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
		time ./target/release/cryptocore --algorithm aes --mode ctr --operation encrypt \
			--key 00112233445566778899aabbccddeeff \
			--input perf_test_10mb.bin \
			--output perf_test_10mb.enc; \
		rm -f perf_test_10mb.bin perf_test_10mb.enc; \
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
	@echo "  test-csprng    - Test CSPRNG module"
	@echo "  test-nist      - Generate NIST test data"
	@echo "  test-nist-full - Run full NIST STS suite"
	@echo "  test-nist-quick- Quick NIST validation"
	@echo "  test-openssl   - Test OpenSSL interoperability"
	@echo "  test-security  - Run security-focused tests"
	@echo "  test-performance - Run performance tests"
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
	@echo "Example usage:"
	@echo "  make dev-test          # Quick development cycle"
	@echo "  make test-nist-full    # Full cryptographic validation"
	@echo "  make test-all          # Complete test suite"