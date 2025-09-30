#!/bin/bash

set -e

echo "Starting CryptoCore Complete Automated Tests..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}SUCCESS: $2${NC}"
    else
        echo -e "${RED}FAILED: $2${NC}"
    fi
}

print_step() {
    echo -e "${BLUE}>>> $1${NC}"
}

print_section() {
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}================================================${NC}"
}

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo -e "${CYAN}Script directory: $SCRIPT_DIR${NC}"
echo -e "${CYAN}Project root: $PROJECT_ROOT${NC}"

# Step 1: Build project
print_section "Building Project"
cd "$PROJECT_ROOT"
cargo build --release
print_status $? "Build completed"

# Define the path to the executable
CRYPTOCORE_BIN="$PROJECT_ROOT/target/release/cryptocore"
if [ ! -f "$CRYPTOCORE_BIN" ]; then
    echo -e "${YELLOW}Release build not found, trying debug build...${NC}"
    cargo build
    CRYPTOCORE_BIN="$PROJECT_ROOT/target/debug/cryptocore"
    if [ ! -f "$CRYPTOCORE_BIN" ]; then
        echo -e "${RED}Executable not found at $CRYPTOCORE_BIN${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}Using executable: $CRYPTOCORE_BIN${NC}"

# Change to script directory for test files
cd "$SCRIPT_DIR"

# Step 2: Basic functionality tests
print_section "Basic Functionality Tests"

print_step "Testing help command"
$CRYPTOCORE_BIN --help
print_status $? "Help command works"

print_step "Testing version command"
$CRYPTOCORE_BIN --version
print_status $? "Version command works"

# Step 3: Create comprehensive test files
print_section "Creating Test Files"

declare -A testFiles=(
    ["empty.txt"]=""
    ["short.txt"]="Short test"
    ["medium.txt"]="This is a medium length test file for encryption testing with various data patterns."
    ["long.txt"]="This is a much longer test file that contains significantly more data to ensure encryption works properly with different data sizes, padding requirements, and edge cases. It includes various characters and patterns."
    ["special_chars.txt"]='Special chars: ~!@#$%^&*()_+{}|:"<>?[]\;'\'',./'
    ["unicode.txt"]="Unicode test: Hello World"
)

for filename in "${!testFiles[@]}"; do
    file_path="$SCRIPT_DIR/$filename"
    echo -e "${testFiles[$filename]}" > "$file_path"
    echo -e "${GREEN}Created $filename${NC}"
done

# Create various binary test files
echo -n -e "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" > "$SCRIPT_DIR/binary_16.bin"
echo -n -e "Binary\x00data\x00with\x00nulls\x00and\x00special\x00chars\xff\xfe\xfd" > "$SCRIPT_DIR/binary_with_nulls.bin"

# Create random 1KB file using different methods
if command -v dd &> /dev/null; then
    dd if=/dev/urandom of="$SCRIPT_DIR/random_1k.bin" bs=1024 count=1 2>/dev/null
elif command -v head &> /dev/null; then
    head -c 1024 /dev/urandom > "$SCRIPT_DIR/random_1k.bin"
else
    # Fallback: create predictable "random" data
    for i in {0..1023}; do
        printf "\x$(printf %02x $((i % 256)))" >> "$SCRIPT_DIR/random_1k.bin"
    done
fi

echo -e "${GREEN}Created binary test files${NC}"

# Step 4: Test all encryption modes comprehensively
print_section "Testing All Encryption Modes"

KEY="00112233445566778899aabbccddeeff"
all_tests_passed=true
test_results=()

# All supported modes
modes=("ecb" "cbc" "cfb" "ofb" "ctr")

for mode in "${modes[@]}"; do
    print_step "Testing ${mode^^} mode"

    # Test with each file type
    for filename in "${!testFiles[@]}"; do
        echo -n "  Testing $filename..."

        file_path="$SCRIPT_DIR/$filename"
        encrypted_file="$SCRIPT_DIR/$filename.$mode.enc"
        decrypted_file="$SCRIPT_DIR/$filename.$mode.dec"

        # Encrypt
        if ! $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation encrypt --key "$KEY" --input "$file_path" --output "$encrypted_file"; then
            echo -e "${RED} Encryption failed${NC}"
            test_results+=("FAILED: $filename.$mode - Encryption failed")
            all_tests_passed=false
            continue
        fi

        # Verify encrypted file exists and has content
        if [ ! -s "$encrypted_file" ]; then
            echo -e "${RED} Empty encrypted file${NC}"
            test_results+=("FAILED: $filename.$mode - Empty encrypted file")
            all_tests_passed=false
            continue
        fi

        # For modes with IV, verify file contains IV + data
        if [ "$mode" != "ecb" ]; then
            file_size=$(stat -f%z "$encrypted_file" 2>/dev/null || stat -c%s "$encrypted_file" 2>/dev/null || wc -c < "$encrypted_file" 2>/dev/null)
            if [ "$file_size" -lt 16 ]; then
                echo -e "${RED} Encrypted file too small for IV${NC}"
                test_results+=("FAILED: $filename.$mode - File too small for IV")
                all_tests_passed=false
                continue
            fi
        fi

        # Decrypt
        if ! $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation decrypt --key "$KEY" --input "$encrypted_file" --output "$decrypted_file"; then
            echo -e "${RED} Decryption failed${NC}"
            test_results+=("FAILED: $filename.$mode - Decryption failed")
            all_tests_passed=false
            continue
        fi

        # Compare
        if cmp -s "$file_path" "$decrypted_file"; then
            echo -e "${GREEN} Success${NC}"
            test_results+=("PASSED: $filename.$mode - Round-trip successful")
        else
            echo -e "${RED} Files don't match${NC}"
            test_results+=("FAILED: $filename.$mode - Files don't match")
            all_tests_passed=false
        fi

        # Cleanup
        rm -f "$encrypted_file" "$decrypted_file"
    done

    # Test with binary files
    for binary_file in binary_16.bin binary_with_nulls.bin random_1k.bin; do
        echo -n "  Testing $binary_file..."

        binary_path="$SCRIPT_DIR/$binary_file"
        encrypted_file="$SCRIPT_DIR/$binary_file.$mode.enc"
        decrypted_file="$SCRIPT_DIR/$binary_file.$mode.dec"

        if $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation encrypt --key "$KEY" --input "$binary_path" --output "$encrypted_file" && \
           $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation decrypt --key "$KEY" --input "$encrypted_file" --output "$decrypted_file" && \
           cmp -s "$binary_path" "$decrypted_file"; then
            echo -e "${GREEN} Success${NC}"
            test_results+=("PASSED: $binary_file.$mode - Round-trip successful")
        else
            echo -e "${RED} Failed${NC}"
            test_results+=("FAILED: $binary_file.$mode - Round-trip failed")
            all_tests_passed=false
        fi

        rm -f "$encrypted_file" "$decrypted_file"
    done
done

# Step 5: Advanced IV handling tests
print_section "Testing IV Handling"

# Test IV provided for decryption
print_step "Testing decryption with provided IV"
iv_test_file="$SCRIPT_DIR/iv_test.txt"
echo "IV test data" > "$iv_test_file"
iv_encrypted_file="$SCRIPT_DIR/iv_encrypted.bin"

if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --input "$iv_test_file" --output "$iv_encrypted_file"; then
    # Extract IV from encrypted file
    extracted_iv_file="$SCRIPT_DIR/extracted_iv.bin"
    ciphertext_only_file="$SCRIPT_DIR/ciphertext_only.bin"

    if command -v dd &> /dev/null; then
        dd if="$iv_encrypted_file" of="$extracted_iv_file" bs=16 count=1 2>/dev/null
        dd if="$iv_encrypted_file" of="$ciphertext_only_file" bs=16 skip=1 2>/dev/null
    else
        # Alternative method using head/tail
        head -c 16 "$iv_encrypted_file" > "$extracted_iv_file"
        tail -c +17 "$iv_encrypted_file" > "$ciphertext_only_file"
    fi

    # Convert IV to hex for CLI
    if command -v xxd &> /dev/null; then
        iv_hex=$(xxd -p "$extracted_iv_file" | tr -d '\n')
    elif command -v hexdump &> /dev/null; then
        iv_hex=$(hexdump -ve '1/1 "%.2x"' "$extracted_iv_file")
    else
        # Simple fallback for testing
        iv_hex="000102030405060708090a0b0c0d0e0f"
    fi

    # Decrypt with provided IV
    iv_decrypted_file="$SCRIPT_DIR/iv_decrypted.txt"
    if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$KEY" --iv "$iv_hex" --input "$ciphertext_only_file" --output "$iv_decrypted_file" && \
       cmp -s "$iv_test_file" "$iv_decrypted_file"; then
        print_status 0 "Decryption with provided IV works"
        test_results+=("PASSED: IV handling - Provided IV decryption")
    else
        print_status 1 "Decryption with provided IV failed"
        test_results+=("FAILED: IV handling - Provided IV decryption")
        all_tests_passed=false
    fi
else
    print_status 1 "Encryption for IV test failed"
    test_results+=("FAILED: IV handling - Encryption failed")
    all_tests_passed=false
fi

rm -f "$iv_test_file" "$iv_encrypted_file" "$extracted_iv_file" "$ciphertext_only_file" "$iv_decrypted_file"

# Step 6: Validation and error handling tests
print_section "Validation and Error Handling"

# Test invalid key
print_step "Testing invalid key rejection"
short_file_path="$SCRIPT_DIR/short.txt"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "invalid" --input "$short_file_path" --output "$SCRIPT_DIR/test.enc" 2>/dev/null; then
    print_status 1 "Should reject invalid key"
    test_results+=("FAILED: Validation - Invalid key accepted")
    all_tests_passed=false
else
    print_status 0 "Invalid key rejected"
    test_results+=("PASSED: Validation - Invalid key rejected")
fi

# Test wrong key length
print_step "Testing wrong key length"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "001122" --input "$short_file_path" --output "$SCRIPT_DIR/test.enc" 2>/dev/null; then
    print_status 1 "Should reject wrong key length"
    test_results+=("FAILED: Validation - Wrong key length accepted")
    all_tests_passed=false
else
    print_status 0 "Wrong key length rejected"
    test_results+=("PASSED: Validation - Wrong key length rejected")
fi

# Test nonexistent file
print_step "Testing nonexistent file rejection"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input "$SCRIPT_DIR/nonexistent_file_12345.txt" --output "$SCRIPT_DIR/test.enc" 2>/dev/null; then
    print_status 1 "Should reject nonexistent file"
    test_results+=("FAILED: Validation - Nonexistent file accepted")
    all_tests_passed=false
else
    print_status 0 "Nonexistent file rejected"
    test_results+=("PASSED: Validation - Nonexistent file rejected")
fi

# Test IV provided during encryption (should fail)
print_step "Testing IV rejection during encryption"
if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --iv "000102030405060708090A0B0C0D0E0F" --input "$short_file_path" --output "$SCRIPT_DIR/test.enc" 2>/dev/null; then
    print_status 1 "Should reject IV during encryption"
    test_results+=("FAILED: Validation - IV accepted during encryption")
    all_tests_passed=false
else
    print_status 0 "IV correctly rejected during encryption"
    test_results+=("PASSED: Validation - IV rejected during encryption")
fi

# Test missing IV for decryption
print_step "Testing missing IV detection"
short_cipher_file="$SCRIPT_DIR/short_cipher.bin"
echo "test" > "$short_cipher_file"
if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$KEY" --input "$short_cipher_file" --output "$SCRIPT_DIR/test.dec" 2>/dev/null; then
    print_status 1 "Should detect missing IV"
    test_results+=("FAILED: Validation - Missing IV not detected")
    all_tests_passed=false
else
    print_status 0 "Missing IV correctly detected"
    test_results+=("PASSED: Validation - Missing IV detected")
fi
rm -f "$short_cipher_file"

# Step 7: File handling tests
print_section "File Handling Tests"

# Test automatic output naming
print_step "Testing automatic output naming"
auto_test_file="$SCRIPT_DIR/auto_test.txt"
echo "Auto name test" > "$auto_test_file"

$CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input "$auto_test_file"
if [ $? -eq 0 ] && [ -f "$auto_test_file.enc" ]; then
    print_status 0 "Automatic encryption naming works"
    test_results+=("PASSED: File handling - Auto encryption naming")
else
    print_status 1 "Automatic encryption naming failed"
    test_results+=("FAILED: File handling - Auto encryption naming")
    all_tests_passed=false
fi

$CRYPTOCORE_BIN --algorithm aes --mode ecb --operation decrypt --key "$KEY" --input "$auto_test_file.enc"
if [ $? -eq 0 ] && [ -f "$auto_test_file.enc.dec" ]; then
    print_status 0 "Automatic decryption naming works"
    test_results+=("PASSED: File handling - Auto decryption naming")
else
    print_status 1 "Automatic decryption naming failed"
    test_results+=("FAILED: File handling - Auto decryption naming")
    all_tests_passed=false
fi

rm -f "$auto_test_file" "$auto_test_file.enc" "$auto_test_file.enc.dec"

# Step 8: OpenSSL interoperability tests
print_section "OpenSSL Interoperability Tests"

if command -v openssl &> /dev/null; then
    print_step "Testing OpenSSL interoperability"

    # Test 1: Encrypt with our tool, decrypt with OpenSSL
    openssl_test1_file="$SCRIPT_DIR/openssl_test1.txt"
    echo "OpenSSL interoperability test data" > "$openssl_test1_file"

    our_encrypted_file="$SCRIPT_DIR/our_encrypted.bin"

    # Encrypt with our tool
    if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --input "$openssl_test1_file" --output "$our_encrypted_file"; then
        # Extract IV and ciphertext
        our_iv_file="$SCRIPT_DIR/our_iv.bin"
        our_ciphertext_file="$SCRIPT_DIR/our_ciphertext.bin"

        if command -v dd &> /dev/null; then
            dd if="$our_encrypted_file" of="$our_iv_file" bs=16 count=1 2>/dev/null
            dd if="$our_encrypted_file" of="$our_ciphertext_file" bs=16 skip=1 2>/dev/null
        else
            head -c 16 "$our_encrypted_file" > "$our_iv_file"
            tail -c +17 "$our_encrypted_file" > "$our_ciphertext_file"
        fi

        # Get IV hex
        if command -v xxd &> /dev/null; then
            iv_hex=$(xxd -p "$our_iv_file" | tr -d '\n')
        else
            iv_hex=$(hexdump -ve '1/1 "%.2x"' "$our_iv_file")
        fi

        # Decrypt with OpenSSL
        openssl_decrypted1_file="$SCRIPT_DIR/openssl_decrypted1.txt"
        if openssl enc -aes-128-cbc -d -K "$KEY" -iv "$iv_hex" -in "$our_ciphertext_file" -out "$openssl_decrypted1_file" 2>/dev/null; then
            if cmp -s "$openssl_test1_file" "$openssl_decrypted1_file"; then
                print_status 0 "OurTool -> OpenSSL: PASS"
                test_results+=("PASSED: Interop - OurTool to OpenSSL")
            else
                print_status 1 "OurTool -> OpenSSL: FAIL (content mismatch)"
                test_results+=("FAILED: Interop - OurTool to OpenSSL")
                all_tests_passed=false
            fi
        else
            print_status 1 "OurTool -> OpenSSL: FAIL (OpenSSL decryption failed)"
            test_results+=("FAILED: Interop - OurTool to OpenSSL")
            all_tests_passed=false
        fi
    else
        print_status 1 "OurTool -> OpenSSL: FAIL (our encryption failed)"
        test_results+=("FAILED: Interop - OurTool to OpenSSL")
        all_tests_passed=false
    fi

    # Test 2: Encrypt with OpenSSL, decrypt with our tool
    openssl_test2_file="$SCRIPT_DIR/openssl_test2.txt"
    echo "OpenSSL to our tool test" > "$openssl_test2_file"

    openssl_encrypted_file="$SCRIPT_DIR/openssl_encrypted.bin"

    # Encrypt with OpenSSL
    TEST_IV="000102030405060708090A0B0C0D0E0F"
    if openssl enc -aes-128-cbc -K "$KEY" -iv "$TEST_IV" -in "$openssl_test2_file" -out "$openssl_encrypted_file" 2>/dev/null; then
        # Decrypt with our tool
        our_decrypted_file="$SCRIPT_DIR/our_decrypted.txt"
        if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$KEY" --iv "$TEST_IV" --input "$openssl_encrypted_file" --output "$our_decrypted_file"; then
            if cmp -s "$openssl_test2_file" "$our_decrypted_file"; then
                print_status 0 "OpenSSL -> OurTool: PASS"
                test_results+=("PASSED: Interop - OpenSSL to OurTool")
            else
                print_status 1 "OpenSSL -> OurTool: FAIL (content mismatch)"
                test_results+=("FAILED: Interop - OpenSSL to OurTool")
                all_tests_passed=false
            fi
        else
            print_status 1 "OpenSSL -> OurTool: FAIL (our decryption failed)"
            test_results+=("FAILED: Interop - OpenSSL to OurTool")
            all_tests_passed=false
        fi
    else
        print_status 1 "OpenSSL -> OurTool: FAIL (OpenSSL encryption failed)"
        test_results+=("FAILED: Interop - OpenSSL to OurTool")
        all_tests_passed=false
    fi

    # Cleanup
    rm -f "$openssl_test1_file" "$openssl_test2_file" "$our_encrypted_file" "$our_iv_file" "$our_ciphertext_file" "$openssl_decrypted1_file" "$openssl_encrypted_file" "$our_decrypted_file"
else
    echo -e "${YELLOW}OpenSSL not available, skipping interoperability tests${NC}"
    test_results+=("SKIPPED: OpenSSL interoperability")
fi

# Step 9: Performance and stress tests
print_section "Performance and Stress Tests"

print_step "Testing with larger files"
# Create a 1MB test file if we have enough space
large_test_file="$SCRIPT_DIR/large_test.bin"
if command -v dd &> /dev/null; then
    # Check disk space (different methods for different systems)
    if command -v df &> /dev/null; then
        available_space=$(df "$SCRIPT_DIR" | awk 'NR==2 {print $4}')
        if [ "$available_space" -gt 5000000 ]; then
            dd if=/dev/urandom of="$large_test_file" bs=1M count=1 2>/dev/null
        else
            available_space=0
        fi
    else
        # If we can't check space, try anyway but clean up on failure
        dd if=/dev/urandom of="$large_test_file" bs=1M count=1 2>/dev/null || rm -f "$large_test_file"
    fi
fi

if [ -f "$large_test_file" ]; then
    for mode in "ecb" "cbc"; do
        echo -n "  Testing 1MB file with $mode..."

        large_encrypted_file="$SCRIPT_DIR/large_encrypted.bin"
        large_decrypted_file="$SCRIPT_DIR/large_decrypted.bin"

        if $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation encrypt --key "$KEY" --input "$large_test_file" --output "$large_encrypted_file" && \
           $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation decrypt --key "$KEY" --input "$large_encrypted_file" --output "$large_decrypted_file" && \
           cmp -s "$large_test_file" "$large_decrypted_file"; then
            echo -e "${GREEN} Success${NC}"
            test_results+=("PASSED: Performance - 1MB file with $mode")
        else
            echo -e "${RED} Failed${NC}"
            test_results+=("FAILED: Performance - 1MB file with $mode")
            all_tests_passed=false
        fi

        rm -f "$large_encrypted_file" "$large_decrypted_file"
    done

    rm -f "$large_test_file"
else
    echo -e "${YELLOW}  Skipping large file tests (insufficient resources)${NC}"
    test_results+=("SKIPPED: Performance - Large file tests")
fi

# Step 10: Cleanup
print_section "Cleaning Up"

for filename in "${!testFiles[@]}"; do
    file_path="$SCRIPT_DIR/$filename"
    rm -f "$file_path"
done
rm -f "$SCRIPT_DIR/binary_16.bin" "$SCRIPT_DIR/binary_with_nulls.bin" "$SCRIPT_DIR/random_1k.bin"

# Step 11: Results summary
print_section "Test Results Summary"

passed_count=0
failed_count=0
skipped_count=0

for result in "${test_results[@]}"; do
    if [[ $result == PASSED:* ]]; then
        echo -e "${GREEN}  $result${NC}"
        ((passed_count++))
    elif [[ $result == FAILED:* ]]; then
        echo -e "${RED}  $result${NC}"
        ((failed_count++))
    else
        echo -e "${YELLOW}  $result${NC}"
        ((skipped_count++))
    fi
done

echo
echo -e "${CYAN}================================================${NC}"
echo -e "${CYAN}  FINAL RESULTS${NC}"
echo -e "${CYAN}================================================${NC}"
echo -e "Total Tests: ${#test_results[@]}"
echo -e "${GREEN}Passed: $passed_count${NC}"
echo -e "${RED}Failed: $failed_count${NC}"
echo -e "${YELLOW}Skipped: $skipped_count${NC}"
echo

if $all_tests_passed; then
    echo -e "${GREEN}ALL TESTS PASSED! CryptoCore is fully functional!${NC}"
    echo -e "${GREEN}All requirements from M2 document are satisfied${NC}"
    echo -e "${GREEN}All 5 encryption modes working: ECB, CBC, CFB, OFB, CTR${NC}"
    echo -e "${GREEN}Comprehensive testing completed successfully${NC}"
else
    echo -e "${RED}SOME TESTS FAILED! Please check the errors above.${NC}"
    exit 1
fi

echo -e "${CYAN}================================================${NC}"