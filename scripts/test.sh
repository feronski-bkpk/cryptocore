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

# Step 1: Build project
print_section "Building Project"
cargo build --release
print_status $? "Build completed"

# Define the path to the executable
CRYPTOCORE_BIN="./target/release/cryptocore"
if [ ! -f "$CRYPTOCORE_BIN" ]; then
    echo -e "${YELLOW}Release build not found, trying debug build...${NC}"
    cargo build
    CRYPTOCORE_BIN="./target/debug/cryptocore"
    if [ ! -f "$CRYPTOCORE_BIN" ]; then
        echo -e "${RED}Executable not found at $CRYPTOCORE_BIN${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}Using executable: $CRYPTOCORE_BIN${NC}"

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
    echo -e "${testFiles[$filename]}" > "$filename"
    echo -e "${GREEN}Created $filename${NC}"
done

# Create various binary test files
echo -n -e "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" > binary_16.bin
echo -n -e "Binary\x00data\x00with\x00nulls\x00and\x00special\x00chars\xff\xfe\xfd" > binary_with_nulls.bin

# Create random 1KB file using different methods
if command -v dd &> /dev/null; then
    dd if=/dev/urandom of=random_1k.bin bs=1024 count=1 2>/dev/null
elif command -v head &> /dev/null; then
    head -c 1024 /dev/urandom > random_1k.bin
else
    # Fallback: create predictable "random" data
    for i in {0..1023}; do
        printf "\x$(printf %02x $((i % 256)))" >> random_1k.bin
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

        encrypted_file="$filename.$mode.enc"
        decrypted_file="$filename.$mode.dec"

        # Encrypt
        if ! $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation encrypt --key "$KEY" --input "$filename" --output "$encrypted_file"; then
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
        if cmp -s "$filename" "$decrypted_file"; then
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

        encrypted_file="$binary_file.$mode.enc"
        decrypted_file="$binary_file.$mode.dec"

        if $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation encrypt --key "$KEY" --input "$binary_file" --output "$encrypted_file" && \
           $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation decrypt --key "$KEY" --input "$encrypted_file" --output "$decrypted_file" && \
           cmp -s "$binary_file" "$decrypted_file"; then
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
echo "IV test data" > iv_test.txt
if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --input iv_test.txt --output iv_encrypted.bin; then
    # Extract IV from encrypted file
    if command -v dd &> /dev/null; then
        dd if=iv_encrypted.bin of=extracted_iv.bin bs=16 count=1 2>/dev/null
        dd if=iv_encrypted.bin of=ciphertext_only.bin bs=16 skip=1 2>/dev/null
    else
        # Alternative method using head/tail
        head -c 16 iv_encrypted.bin > extracted_iv.bin
        tail -c +17 iv_encrypted.bin > ciphertext_only.bin
    fi

    # Convert IV to hex for CLI
    if command -v xxd &> /dev/null; then
        iv_hex=$(xxd -p extracted_iv.bin | tr -d '\n')
    elif command -v hexdump &> /dev/null; then
        iv_hex=$(hexdump -ve '1/1 "%.2x"' extracted_iv.bin)
    else
        # Simple fallback for testing
        iv_hex="000102030405060708090a0b0c0d0e0f"
    fi

    # Decrypt with provided IV
    if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$KEY" --iv "$iv_hex" --input ciphertext_only.bin --output iv_decrypted.txt && \
       cmp -s iv_test.txt iv_decrypted.txt; then
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

rm -f iv_test.txt iv_encrypted.bin extracted_iv.bin ciphertext_only.bin iv_decrypted.txt

# Step 6: Validation and error handling tests
print_section "Validation and Error Handling"

# Test invalid key
print_step "Testing invalid key rejection"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "invalid" --input "short.txt" --output "test.enc" 2>/dev/null; then
    print_status 1 "Should reject invalid key"
    test_results+=("FAILED: Validation - Invalid key accepted")
    all_tests_passed=false
else
    print_status 0 "Invalid key rejected"
    test_results+=("PASSED: Validation - Invalid key rejected")
fi

# Test wrong key length
print_step "Testing wrong key length"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "001122" --input "short.txt" --output "test.enc" 2>/dev/null; then
    print_status 1 "Should reject wrong key length"
    test_results+=("FAILED: Validation - Wrong key length accepted")
    all_tests_passed=false
else
    print_status 0 "Wrong key length rejected"
    test_results+=("PASSED: Validation - Wrong key length rejected")
fi

# Test nonexistent file
print_step "Testing nonexistent file rejection"
if $CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input "nonexistent_file_12345.txt" --output "test.enc" 2>/dev/null; then
    print_status 1 "Should reject nonexistent file"
    test_results+=("FAILED: Validation - Nonexistent file accepted")
    all_tests_passed=false
else
    print_status 0 "Nonexistent file rejected"
    test_results+=("PASSED: Validation - Nonexistent file rejected")
fi

# Test IV provided during encryption (should fail)
print_step "Testing IV rejection during encryption"
if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --iv "000102030405060708090A0B0C0D0E0F" --input "short.txt" --output "test.enc" 2>/dev/null; then
    print_status 1 "Should reject IV during encryption"
    test_results+=("FAILED: Validation - IV accepted during encryption")
    all_tests_passed=false
else
    print_status 0 "IV correctly rejected during encryption"
    test_results+=("PASSED: Validation - IV rejected during encryption")
fi

# Test missing IV for decryption
print_step "Testing missing IV detection"
echo "test" > short_cipher.bin
if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$KEY" --input "short_cipher.bin" --output "test.dec" 2>/dev/null; then
    print_status 1 "Should detect missing IV"
    test_results+=("FAILED: Validation - Missing IV not detected")
    all_tests_passed=false
else
    print_status 0 "Missing IV correctly detected"
    test_results+=("PASSED: Validation - Missing IV detected")
fi
rm -f short_cipher.bin

# Step 7: File handling tests
print_section "File Handling Tests"

# Test automatic output naming
print_step "Testing automatic output naming"
echo "Auto name test" > auto_test.txt

$CRYPTOCORE_BIN --algorithm aes --mode ecb --operation encrypt --key "$KEY" --input auto_test.txt
if [ $? -eq 0 ] && [ -f "auto_test.txt.enc" ]; then
    print_status 0 "Automatic encryption naming works"
    test_results+=("PASSED: File handling - Auto encryption naming")
else
    print_status 1 "Automatic encryption naming failed"
    test_results+=("FAILED: File handling - Auto encryption naming")
    all_tests_passed=false
fi

$CRYPTOCORE_BIN --algorithm aes --mode ecb --operation decrypt --key "$KEY" --input auto_test.txt.enc
if [ $? -eq 0 ] && [ -f "auto_test.txt.enc.dec" ]; then
    print_status 0 "Automatic decryption naming works"
    test_results+=("PASSED: File handling - Auto decryption naming")
else
    print_status 1 "Automatic decryption naming failed"
    test_results+=("FAILED: File handling - Auto decryption naming")
    all_tests_passed=false
fi

rm -f auto_test.txt auto_test.txt.enc auto_test.txt.enc.dec

# Step 8: OpenSSL interoperability tests
print_section "OpenSSL Interoperability Tests"

if command -v openssl &> /dev/null; then
    print_step "Testing OpenSSL interoperability"

    # Test 1: Encrypt with our tool, decrypt with OpenSSL
    echo "OpenSSL interoperability test data" > openssl_test1.txt

    # Encrypt with our tool
    if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation encrypt --key "$KEY" --input openssl_test1.txt --output our_encrypted.bin; then
        # Extract IV and ciphertext
        if command -v dd &> /dev/null; then
            dd if=our_encrypted.bin of=our_iv.bin bs=16 count=1 2>/dev/null
            dd if=our_encrypted.bin of=our_ciphertext.bin bs=16 skip=1 2>/dev/null
        else
            head -c 16 our_encrypted.bin > our_iv.bin
            tail -c +17 our_encrypted.bin > our_ciphertext.bin
        fi

        # Get IV hex
        if command -v xxd &> /dev/null; then
            iv_hex=$(xxd -p our_iv.bin | tr -d '\n')
        else
            iv_hex=$(hexdump -ve '1/1 "%.2x"' our_iv.bin)
        fi

        # Decrypt with OpenSSL
        if openssl enc -aes-128-cbc -d -K "$KEY" -iv "$iv_hex" -in our_ciphertext.bin -out openssl_decrypted1.txt 2>/dev/null; then
            if cmp -s openssl_test1.txt openssl_decrypted1.txt; then
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
    echo "OpenSSL to our tool test" > openssl_test2.txt

    # Encrypt with OpenSSL
    TEST_IV="000102030405060708090A0B0C0D0E0F"
    if openssl enc -aes-128-cbc -K "$KEY" -iv "$TEST_IV" -in openssl_test2.txt -out openssl_encrypted.bin 2>/dev/null; then
        # Decrypt with our tool
        if $CRYPTOCORE_BIN --algorithm aes --mode cbc --operation decrypt --key "$KEY" --iv "$TEST_IV" --input openssl_encrypted.bin --output our_decrypted.txt; then
            if cmp -s openssl_test2.txt our_decrypted.txt; then
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
    rm -f openssl_test1.txt openssl_test2.txt our_encrypted.bin our_iv.bin our_ciphertext.bin openssl_decrypted1.txt openssl_encrypted.bin our_decrypted.txt
else
    echo -e "${YELLOW}OpenSSL not available, skipping interoperability tests${NC}"
    test_results+=("SKIPPED: OpenSSL interoperability")
fi

# Step 9: Performance and stress tests
print_section "Performance and Stress Tests"

print_step "Testing with larger files"
# Create a 1MB test file if we have enough space
if command -v dd &> /dev/null; then
    # Check disk space (different methods for different systems)
    if command -v df &> /dev/null; then
        available_space=$(df . | awk 'NR==2 {print $4}')
        if [ "$available_space" -gt 5000000 ]; then
            dd if=/dev/urandom of=large_test.bin bs=1M count=1 2>/dev/null
        else
            available_space=0
        fi
    else
        # If we can't check space, try anyway but clean up on failure
        dd if=/dev/urandom of=large_test.bin bs=1M count=1 2>/dev/null || rm -f large_test.bin
    fi
fi

if [ -f "large_test.bin" ]; then
    for mode in "ecb" "cbc"; do
        echo -n "  Testing 1MB file with $mode..."

        if $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation encrypt --key "$KEY" --input large_test.bin --output large_encrypted.bin && \
           $CRYPTOCORE_BIN --algorithm aes --mode "$mode" --operation decrypt --key "$KEY" --input large_encrypted.bin --output large_decrypted.bin && \
           cmp -s large_test.bin large_decrypted.bin; then
            echo -e "${GREEN} Success${NC}"
            test_results+=("PASSED: Performance - 1MB file with $mode")
        else
            echo -e "${RED} Failed${NC}"
            test_results+=("FAILED: Performance - 1MB file with $mode")
            all_tests_passed=false
        fi

        rm -f large_encrypted.bin large_decrypted.bin
    done

    rm -f large_test.bin
else
    echo -e "${YELLOW}  Skipping large file tests (insufficient resources)${NC}"
    test_results+=("SKIPPED: Performance - Large file tests")
fi

# Step 10: Cleanup
print_section "Cleaning Up"

for filename in "${!testFiles[@]}"; do
    rm -f "$filename"
done
rm -f binary_16.bin binary_with_nulls.bin random_1k.bin

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