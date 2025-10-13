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

write_status() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}SUCCESS: $2${NC}"
    else
        echo -e "${RED}FAILED: $2${NC}"
    fi
}

write_step() {
    echo -e "${BLUE}>>> $1${NC}"
}

write_section() {
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
write_section "Building Project"
cd "$PROJECT_ROOT"
cargo build --release
if [ $? -ne 0 ]; then
    echo -e "${RED}Build failed!${NC}"
    exit 1
fi
write_status 0 "Build completed"

# Define the path to the executable
CRYPTOCORE_BIN="$PROJECT_ROOT/target/release/cryptocore"
if [ ! -f "$CRYPTOCORE_BIN" ]; then
    echo -e "${YELLOW}Executable not found at $CRYPTOCORE_BIN${NC}"
    echo -e "${YELLOW}Trying debug build...${NC}"
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
write_section "Basic Functionality Tests"

write_step "Testing help command"
$CRYPTOCORE_BIN --help
write_status $? "Help command works"

write_step "Testing version command"
$CRYPTOCORE_BIN --version
write_status $? "Version command works"

# Step 3: Create comprehensive test files
write_section "Creating Test Files"

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

# Create binary test files
# binary_16.bin
echo -n -e "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" > "$SCRIPT_DIR/binary_16.bin"

# binary_with_nulls.bin
echo -n -e "\x42\x69\x6E\x61\x72\x79\x00\x64\x61\x74\x61\x00\x77\x69\x74\x68\x00\x6E\x75\x6C\x6C\x73\x00\x61\x6E\x64\x00\x73\x70\x65\x63\x69\x61\x6C\x00\x63\x68\x61\x72\x73\xFF\xFE\xFD" > "$SCRIPT_DIR/binary_with_nulls.bin"

# Create random 1KB file
if command -v dd &> /dev/null; then
    dd if=/dev/urandom of="$SCRIPT_DIR/random_1k.bin" bs=1024 count=1 2>/dev/null
else
    # Fallback using /dev/urandom with head
    head -c 1024 /dev/urandom > "$SCRIPT_DIR/random_1k.bin" 2>/dev/null || {
        # Ultimate fallback - create deterministic "random" data
        python -c "import os; open('$SCRIPT_DIR/random_1k.bin', 'wb').write(os.urandom(1024))" 2>/dev/null || {
            for i in {0..1023}; do
                printf "\\x$(printf %02x $((RANDOM % 256)))" >> "$SCRIPT_DIR/random_1k.bin"
            done
        }
    }
fi

echo -e "${GREEN}Created binary test files${NC}"

# Step 4: CSPRNG Module Tests
write_section "CSPRNG Module Tests"

write_step "Testing CSPRNG module"
cargo test --test csprng -- --nocapture
write_status $? "CSPRNG module tests"

# Initialize test tracking variables
all_tests_passed=true
test_results=()
KEY="00112233445566778899aabbccddeeff"

# Step 5: Automatic Key Generation Tests
write_section "Automatic Key Generation Tests"

write_step "Testing encryption without --key parameter"
auto_key_test_file="$SCRIPT_DIR/auto_key_test.txt"
echo "Testing automatic key generation" > "$auto_key_test_file"

# Run encryption without key
auto_key_output=$($CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --input "$auto_key_test_file" --output "$auto_key_test_file.enc" 2>&1)
auto_key_success=$?

if [ $auto_key_success -eq 0 ]; then
    # Check if key was generated and printed
    if echo "$auto_key_output" | grep -q "Generated random key: [0-9a-f]\{32\}"; then
        generated_key=$(echo "$auto_key_output" | grep -o "Generated random key: [0-9a-f]\{32\}" | cut -d' ' -f4)
        echo -e "${GREEN}Generated key: $generated_key${NC}"

        # Test decryption with generated key
        $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$generated_key" --input "$auto_key_test_file.enc" --output "$auto_key_test_file.dec"
        decrypt_success=$?

        if [ $decrypt_success -eq 0 ]; then
            original_content=$(cat "$auto_key_test_file")
            decrypted_content=$(cat "$auto_key_test_file.dec")

            if [ "$original_content" = "$decrypted_content" ]; then
                write_status 0 "Automatic key generation and usage"
                test_results+=("PASSED: Auto Key - Generation and usage")
            else
                write_status 1 "Automatic key generation (content mismatch)"
                test_results+=("FAILED: Auto Key - Content mismatch")
                all_tests_passed=false
            fi
        else
            write_status 1 "Automatic key generation (decryption failed)"
            test_results+=("FAILED: Auto Key - Decryption failed")
            all_tests_passed=false
        fi
    else
        write_status 1 "Automatic key generation (no key output)"
        echo -e "${YELLOW}Output was: $auto_key_output${NC}"
        test_results+=("FAILED: Auto Key - No key output")
        all_tests_passed=false
    fi
else
    write_status 1 "Automatic key generation (encryption failed)"
    echo -e "${YELLOW}Output was: $auto_key_output${NC}"
    test_results+=("FAILED: Auto Key - Encryption failed")
    all_tests_passed=false
fi

rm -f "$auto_key_test_file" "$auto_key_test_file.enc" "$auto_key_test_file.dec"

# Step 6: Weak Key Detection Tests
write_section "Weak Key Detection Tests"

write_step "Testing weak key detection"
weak_key_test_file="$SCRIPT_DIR/weak_key_test.txt"
echo "Weak key test" > "$weak_key_test_file"

# Test all zeros key (should show warning but work)
weak_key_output=$($CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "00000000000000000000000000000000" --input "$weak_key_test_file" --output "$weak_key_test_file.enc" 2>&1)
weak_key_warning=$(echo "$weak_key_output" | grep -q "WARNING.*weak" && echo true || echo false)
weak_key_success=$?

if [ "$weak_key_warning" = "true" ] && [ $weak_key_success -eq 0 ]; then
    write_status 0 "Weak key detection with all zeros"
    test_results+=("PASSED: Weak Key - All zeros detection")
else
    write_status 1 "Weak key detection failed"
    test_results+=("FAILED: Weak Key - All zeros detection")
    all_tests_passed=false
fi

# Test sequential key (should show warning but work)
sequential_key_output=$($CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "000102030405060708090a0b0c0d0e0f" --input "$weak_key_test_file" --output "$weak_key_test_file.enc2" 2>&1)
sequential_key_warning=$(echo "$sequential_key_output" | grep -q "WARNING.*weak" && echo true || echo false)
sequential_key_success=$?

if [ "$sequential_key_warning" = "true" ] && [ $sequential_key_success -eq 0 ]; then
    write_status 0 "Weak key detection with sequential bytes"
    test_results+=("PASSED: Weak Key - Sequential bytes detection")
else
    write_status 1 "Sequential key detection failed"
    test_results+=("FAILED: Weak Key - Sequential bytes detection")
    all_tests_passed=false
fi

rm -f "$weak_key_test_file" "$weak_key_test_file.enc" "$weak_key_test_file.enc2"

# Step 7: Test all encryption modes comprehensively
write_section "Testing All Encryption Modes"

# All supported modes
modes=("ecb" "cbc" "cfb" "ofb" "ctr")

for mode in "${modes[@]}"; do
    write_step "Testing ${mode^^} mode"

    # Test with each file type
    for filename in "${!testFiles[@]}"; do
        file_path="$SCRIPT_DIR/$filename"
        echo -n "  Testing $filename..."

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
        if [ ! -f "$encrypted_file" ] || [ ! -s "$encrypted_file" ]; then
            echo -e "${RED} Empty encrypted file${NC}"
            test_results+=("FAILED: $filename.$mode - Empty encrypted file")
            all_tests_passed=false
            continue
        fi

        # For modes with IV, verify file contains IV + data
        if [ "$mode" != "ecb" ]; then
            file_size=$(wc -c < "$encrypted_file" 2>/dev/null || stat -c%s "$encrypted_file" 2>/dev/null || stat -f%z "$encrypted_file" 2>/dev/null)
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

        # Compare files as bytes
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
    binary_files=("binary_16.bin" "binary_with_nulls.bin" "random_1k.bin")
    for binary_file in "${binary_files[@]}"; do
        echo -n "  Testing $binary_file..."

        binary_path="$SCRIPT_DIR/$binary_file"
        encrypted_file="$SCRIPT_DIR/$binary_file.$mode.enc"
        decrypted_file="$SCRIPT_DIR/$binary_file.$mode.dec"

        # Encrypt
        if ! $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation encrypt --key "$KEY" --input "$binary_path" --output "$encrypted_file"; then
            echo -e "${RED} Encryption failed${NC}"
            test_results+=("FAILED: $binary_file.$mode - Encryption failed")
            all_tests_passed=false
            continue
        fi

        # Decrypt
        if ! $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation decrypt --key "$KEY" --input "$encrypted_file" --output "$decrypted_file"; then
            echo -e "${RED} Decryption failed${NC}"
            test_results+=("FAILED: $binary_file.$mode - Decryption failed")
            all_tests_passed=false
            continue
        fi

        # Compare binary files
        if cmp -s "$binary_path" "$decrypted_file"; then
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

# Step 8: Advanced IV handling tests
write_section "Testing IV Handling"

# Test IV provided for decryption
write_step "Testing decryption with provided IV"
iv_test_file="$SCRIPT_DIR/iv_test.txt"
echo "IV test data" > "$iv_test_file"
iv_encrypted_file="$SCRIPT_DIR/iv_encrypted.bin"

# Encrypt with auto IV
if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --input "$iv_test_file" --output "$iv_encrypted_file"; then
    # Extract IV from encrypted file
    encrypted_data_size=$(wc -c < "$iv_encrypted_file")
    if [ "$encrypted_data_size" -lt 16 ]; then
        write_status 1 "Encrypted file too small for IV extraction"
        test_results+=("FAILED: IV handling - File too small")
        all_tests_passed=false
    else
        # Extract first 16 bytes as IV
        iv_hex=$(head -c 16 "$iv_encrypted_file" | xxd -p | tr -d '\n')
        # Extract remaining as ciphertext
        tail -c +17 "$iv_encrypted_file" > "$SCRIPT_DIR/ciphertext_only.bin"

        ciphertext_file="$SCRIPT_DIR/ciphertext_only.bin"
        iv_decrypted_file="$SCRIPT_DIR/iv_decrypted.txt"

        # Decrypt with provided IV
        if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$KEY" --iv "$iv_hex" --input "$ciphertext_file" --output "$iv_decrypted_file"; then
            if cmp -s "$iv_test_file" "$iv_decrypted_file"; then
                write_status 0 "Decryption with provided IV works"
                test_results+=("PASSED: IV handling - Provided IV decryption")
            else
                write_status 1 "Decryption with provided IV failed (content mismatch)"
                test_results+=("FAILED: IV handling - Provided IV decryption")
                all_tests_passed=false
            fi
        else
            write_status 1 "Decryption with provided IV failed"
            test_results+=("FAILED: IV handling - Provided IV decryption")
            all_tests_passed=false
        fi
    fi
else
    write_status 1 "Encryption for IV test failed"
    test_results+=("FAILED: IV handling - Encryption failed")
    all_tests_passed=false
fi

rm -f "$iv_test_file" "$iv_encrypted_file" "$ciphertext_file" "$iv_decrypted_file" 2>/dev/null

# Step 9: Validation and error handling tests
write_section "Validation and Error Handling"

# Test invalid key
write_step "Testing invalid key rejection"
short_file_path="$SCRIPT_DIR/short.txt"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "invalid" --input "$short_file_path" --output "$SCRIPT_DIR/test.enc" 2>/dev/null; then
    write_status 1 "Should reject invalid key"
    test_results+=("FAILED: Validation - Invalid key accepted")
    all_tests_passed=false
else
    write_status 0 "Invalid key rejected"
    test_results+=("PASSED: Validation - Invalid key rejected")
fi

# Test wrong key length
write_step "Testing wrong key length"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "001122" --input "$short_file_path" --output "$SCRIPT_DIR/test.enc" 2>/dev/null; then
    write_status 1 "Should reject wrong key length"
    test_results+=("FAILED: Validation - Wrong key length accepted")
    all_tests_passed=false
else
    write_status 0 "Wrong key length rejected"
    test_results+=("PASSED: Validation - Wrong key length rejected")
fi

# Test nonexistent file
write_step "Testing nonexistent file rejection"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input "$SCRIPT_DIR/nonexistent_file_12345.txt" --output "$SCRIPT_DIR/test.enc" 2>/dev/null; then
    write_status 1 "Should reject nonexistent file"
    test_results+=("FAILED: Validation - Nonexistent file accepted")
    all_tests_passed=false
else
    write_status 0 "Nonexistent file rejected"
    test_results+=("PASSED: Validation - Nonexistent file rejected")
fi

# Test IV provided during encryption (should fail)
write_step "Testing IV rejection during encryption"
if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --iv "000102030405060708090A0B0C0D0E0F" --input "$short_file_path" --output "$SCRIPT_DIR/test.enc" 2>/dev/null; then
    write_status 1 "Should reject IV during encryption"
    test_results+=("FAILED: Validation - IV accepted during encryption")
    all_tests_passed=false
else
    write_status 0 "IV correctly rejected during encryption"
    test_results+=("PASSED: Validation - IV rejected during encryption")
fi

# Test missing IV for decryption
write_step "Testing missing IV detection"
short_cipher_file="$SCRIPT_DIR/short_cipher.bin"
echo "test" > "$short_cipher_file"
if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$KEY" --input "$short_cipher_file" --output "$SCRIPT_DIR/test.dec" 2>/dev/null; then
    write_status 1 "Should detect missing IV"
    test_results+=("FAILED: Validation - Missing IV not detected")
    all_tests_passed=false
else
    write_status 0 "Missing IV correctly detected"
    test_results+=("PASSED: Validation - Missing IV detected")
fi
rm -f "$short_cipher_file"

# Step 10: File handling tests
write_section "File Handling Tests"

# Test automatic output naming
write_step "Testing automatic output naming"
auto_test_file="$SCRIPT_DIR/auto_test.txt"
echo "Auto name test" > "$auto_test_file"

$CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input "$auto_test_file"
if [ $? -eq 0 ] && [ -f "$auto_test_file.enc" ]; then
    write_status 0 "Automatic encryption naming works"
    test_results+=("PASSED: File handling - Auto encryption naming")
else
    write_status 1 "Automatic encryption naming failed"
    test_results+=("FAILED: File handling - Auto encryption naming")
    all_tests_passed=false
fi

$CRYPTOCORE_BIN --algorithm aes --mode ecb --operation decrypt --key "$KEY" --input "$auto_test_file.enc"
if [ $? -eq 0 ] && [ -f "$auto_test_file.enc.dec" ]; then
    write_status 0 "Automatic decryption naming works"
    test_results+=("PASSED: File handling - Auto decryption naming")
else
    write_status 1 "Automatic decryption naming failed"
    test_results+=("FAILED: File handling - Auto decryption naming")
    all_tests_passed=false
fi

rm -f "$auto_test_file" "$auto_test_file.enc" "$auto_test_file.enc.dec"

# Step 11: OpenSSL interoperability tests
write_section "OpenSSL Interoperability Tests"

if command -v openssl &> /dev/null; then
    write_step "Testing OpenSSL interoperability"

    # Test 1: Encrypt with our tool, decrypt with OpenSSL
    openssl_test1_file="$SCRIPT_DIR/openssl_test1.txt"
    echo "OpenSSL interoperability test data" > "$openssl_test1_file"
    our_encrypted_file="$SCRIPT_DIR/our_encrypted.bin"

    # Encrypt with our tool
    if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --input "$openssl_test1_file" --output "$our_encrypted_file"; then
        # Extract IV and ciphertext
        iv_file="$SCRIPT_DIR/our_iv.bin"
        ciphertext_file="$SCRIPT_DIR/our_ciphertext.bin"

        head -c 16 "$our_encrypted_file" > "$iv_file"
        tail -c +17 "$our_encrypted_file" > "$ciphertext_file"

        # Convert IV to hex for OpenSSL
        iv_hex=$(xxd -p "$iv_file" | tr -d '\n')

        # Decrypt with OpenSSL
        openssl_decrypted_file="$SCRIPT_DIR/openssl_decrypted1.txt"
        if openssl enc -aes-128-cbc -d -K "$KEY" -iv "$iv_hex" -in "$ciphertext_file" -out "$openssl_decrypted_file" 2>/dev/null; then
            if cmp -s "$openssl_test1_file" "$openssl_decrypted_file"; then
                write_status 0 "OurTool -> OpenSSL: PASS"
                test_results+=("PASSED: Interop - OurTool to OpenSSL")
            else
                write_status 1 "OurTool -> OpenSSL: FAIL (content mismatch)"
                test_results+=("FAILED: Interop - OurTool to OpenSSL")
                all_tests_passed=false
            fi
        else
            write_status 1 "OurTool -> OpenSSL: FAIL (OpenSSL decryption failed)"
            test_results+=("FAILED: Interop - OurTool to OpenSSL")
            all_tests_passed=false
        fi
    else
        write_status 1 "OurTool -> OpenSSL: FAIL (our encryption failed)"
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
                write_status 0 "OpenSSL -> OurTool: PASS"
                test_results+=("PASSED: Interop - OpenSSL to OurTool")
            else
                write_status 1 "OpenSSL -> OurTool: FAIL (content mismatch)"
                test_results+=("FAILED: Interop - OpenSSL to OurTool")
                all_tests_passed=false
            fi
        else
            write_status 1 "OpenSSL -> OurTool: FAIL (our decryption failed)"
            test_results+=("FAILED: Interop - OpenSSL to OurTool")
            all_tests_passed=false
        fi
    else
        write_status 1 "OpenSSL -> OurTool: FAIL (OpenSSL encryption failed)"
        test_results+=("FAILED: Interop - OpenSSL to OurTool")
        all_tests_passed=false
    fi

    # Cleanup
    rm -f "$openssl_test1_file" "$openssl_test2_file" "$our_encrypted_file" "$iv_file" "$ciphertext_file" "$openssl_decrypted_file" "$openssl_encrypted_file" "$our_decrypted_file"
else
    echo -e "${YELLOW}OpenSSL not available, skipping interoperability tests${NC}"
    test_results+=("SKIPPED: OpenSSL interoperability")
fi

# Step 12: Performance and stress tests
write_section "Performance and Stress Tests"

write_step "Testing with larger files"
# Create a larger test file if we have enough space
large_test_file="$SCRIPT_DIR/large_test.bin"
# Create 1MB file
if command -v dd &> /dev/null; then
    dd if=/dev/urandom of="$large_test_file" bs=1M count=1 2>/dev/null
else
    head -c 1048576 /dev/urandom > "$large_test_file" 2>/dev/null
fi

if [ -f "$large_test_file" ] && [ -s "$large_test_file" ]; then
    for mode in "ecb" "cbc"; do
        echo -n "  Testing 1MB file with $mode..."

        large_encrypted_file="$SCRIPT_DIR/large_encrypted.bin"
        large_decrypted_file="$SCRIPT_DIR/large_decrypted.bin"

        # Encrypt
        if $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation encrypt --key "$KEY" --input "$large_test_file" --output "$large_encrypted_file"; then
            encrypt_success=0
        else
            encrypt_success=1
        fi

        # Decrypt
        if [ $encrypt_success -eq 0 ] && $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation decrypt --key "$KEY" --input "$large_encrypted_file" --output "$large_decrypted_file"; then
            decrypt_success=0
        else
            decrypt_success=1
        fi

        if [ $encrypt_success -eq 0 ] && [ $decrypt_success -eq 0 ]; then
            # Compare files (check first and last 100 bytes for performance)
            if cmp -s "$large_test_file" "$large_decrypted_file"; then
                echo -e "${GREEN} Success${NC}"
                test_results+=("PASSED: Performance - 1MB file with $mode")
            else
                echo -e "${RED} Content mismatch${NC}"
                test_results+=("FAILED: Performance - 1MB file with $mode")
                all_tests_passed=false
            fi
        else
            echo -e "${RED} Execution failed${NC}"
            test_results+=("FAILED: Performance - 1MB file with $mode")
            all_tests_passed=false
        fi

        rm -f "$large_encrypted_file" "$large_decrypted_file"
    done

    rm -f "$large_test_file"
else
    echo -e "${YELLOW}  Skipping large file tests (insufficient disk space)${NC}"
    test_results+=("SKIPPED: Performance - Large file tests")
fi

# Step 13: Cleanup
write_section "Cleaning Up"

for filename in "${!testFiles[@]}"; do
    rm -f "$SCRIPT_DIR/$filename"
done
rm -f "$SCRIPT_DIR/binary_16.bin" "$SCRIPT_DIR/binary_with_nulls.bin" "$SCRIPT_DIR/random_1k.bin"

# Step 14: Results summary
write_section "Test Results Summary"

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
    echo -e "${GREEN}All requirements from M3 document are satisfied${NC}"
    echo -e "${GREEN}CSPRNG module working with automatic key generation${NC}"
    echo -e "${GREEN}All 5 encryption modes working: ECB, CBC, CFB, OFB, CTR${NC}"
    echo -e "${GREEN}Comprehensive testing completed successfully${NC}"
    echo -e "${GREEN}File handling, validation, and interoperability verified${NC}"
else
    echo -e "${RED}SOME TESTS FAILED! Please check the errors above.${NC}"
    exit 1
fi

echo -e "${CYAN}================================================${NC}"