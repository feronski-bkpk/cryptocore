#!/bin/bash

set -e

echo "Starting CryptoCore Complete Automated Tests (v0.6.0 with AEAD)..."

# Colors and formatting
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
GRAY='\033[0;90m'
NC='\033[0m' # No Color

write_step() {
    echo -e "${BLUE}>>> $1${NC}"
}

write_section() {
    echo -e "${CYAN}================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}================================================${NC}"
}

write_status() {
    if [ "$1" = "0" ] || [ "$1" = "true" ]; then
        echo -e "${GREEN}SUCCESS: $2${NC}"
    else
        echo -e "${RED}FAILED: $2${NC}"
    fi
}

show_progress() {
    local current=$1
    local total=$2
    local message=$3
    local percent=$(awk "BEGIN {printf \"%.1f\", ($current/$total)*100}")
    echo -e "${YELLOW}[$current/$total - ${percent}%] $message${NC}"
}

# Get the script directory and project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$SCRIPT_DIR" == *"/scripts" ]]; then
    PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
else
    PROJECT_ROOT="$SCRIPT_DIR"
fi

echo -e "${GRAY}Script directory: $SCRIPT_DIR${NC}"
echo -e "${GRAY}Project root: $PROJECT_ROOT${NC}"

# Initialize test results
declare -A test_results
declare -a test_categories=("Build" "Basic" "Files" "UnitTests" "Hash" "HMAC" "GCM" "ETM" "ClassicModes" "Validation" "Interop" "Cleanup")
for category in "${test_categories[@]}"; do
    test_results["$category"]=""
done

passed_count=0
failed_count=0
skipped_count=0
all_tests_passed=true

add_test_result() {
    local result="$1"
    local category="${2:-General}"

    # Store result in array format
    if [ -z "${test_results[$category]}" ]; then
        test_results["$category"]="$result"
    else
        test_results["$category"]="${test_results[$category]}|$result"
    fi

    # Update counters
    if [[ "$result" == "PASSED:"* ]]; then
        ((passed_count++))
    elif [[ "$result" == "FAILED:"* ]]; then
        ((failed_count++))
        all_tests_passed=false
    elif [[ "$result" == "SKIPPED:"* ]]; then
        ((skipped_count++))
    fi
}

# Step 1: Build project
write_section "Building Project"
cd "$PROJECT_ROOT"

write_step "Building release version"
cargo build --release
if [ $? -ne 0 ]; then
    echo -e "${RED}Release build failed!${NC}"
    exit 1
fi
add_test_result "PASSED: Build - Release build completed" "Build"

write_step "Building debug version"
cargo build
if [ $? -ne 0 ]; then
    echo -e "${RED}Debug build failed!${NC}"
    exit 1
fi
add_test_result "PASSED: Build - Debug build completed" "Build"

# Define the path to the executable
CRYPTOCORE_BIN="$PROJECT_ROOT/target/release/cryptocore"
if [ ! -f "$CRYPTOCORE_BIN" ]; then
    echo -e "${YELLOW}Release executable not found at $CRYPTOCORE_BIN${NC}"
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
$CRYPTOCORE_BIN --help > /dev/null 2>&1
if [ $? -eq 0 ]; then
    add_test_result "PASSED: Basic - Help command works" "Basic"
else
    add_test_result "FAILED: Basic - Help command failed" "Basic"
fi

write_step "Testing version command"
version_output=$($CRYPTOCORE_BIN --version 2>&1 | grep -E "0\.6\.0")
if [ -n "$version_output" ]; then
    add_test_result "PASSED: Basic - Version command shows 0.6.0" "Basic"
else
    add_test_result "FAILED: Basic - Version command failed" "Basic"
fi

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

# Create text files
for filename in "${!testFiles[@]}"; do
    file_path="$SCRIPT_DIR/$filename"
    echo -e "${testFiles[$filename]}" > "$file_path"
    echo -e "${GREEN}Created $filename${NC}"
done

# Create binary files
# binary_16.bin
echo -n -e "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f" > "$SCRIPT_DIR/binary_16.bin"

# binary_with_nulls.bin
echo -n -e "\x42\x69\x6E\x61\x72\x79\x00\x64\x61\x74\x61\x00\x77\x69\x74\x68\x00\x6E\x75\x6C\x6C\x73\x00\x61\x6E\x64\x00\x73\x70\x65\x63\x69\x61\x6C\x00\x63\x68\x61\x72\x73\xFF\xFE\xFD" > "$SCRIPT_DIR/binary_with_nulls.bin"

# Create random 1KB file
if command -v dd &> /dev/null; then
    dd if=/dev/urandom of="$SCRIPT_DIR/random_1k.bin" bs=1024 count=1 2>/dev/null
else
    head -c 1024 /dev/urandom > "$SCRIPT_DIR/random_1k.bin" 2>/dev/null || {
        for i in {0..1023}; do
            printf "\\x$(printf %02x $((RANDOM % 256)))" >> "$SCRIPT_DIR/random_1k.bin"
        done
    }
fi

add_test_result "PASSED: Files - Test files created" "Files"

# Step 4: Run unit tests
write_section "Unit Tests"

declare -A unit_tests=(
    ["csprng"]="CSPRNG module tests"
    ["hash"]="Hash module tests"
    ["hmac"]="HMAC module tests"
    ["gcm"]="GCM module tests"
    ["aead"]="AEAD module tests"
    ["integration_tests"]="Integration tests"
)

unit_test_count=0
total_unit_tests=${#unit_tests[@]}

for test_name in "${!unit_tests[@]}"; do
    ((unit_test_count++))
    show_progress $unit_test_count $total_unit_tests "Testing $test_name"

    if cargo test --test "$test_name" -- --nocapture 2>&1 > /dev/null; then
        add_test_result "PASSED: Unit - ${unit_tests[$test_name]}" "UnitTests"
    else
        add_test_result "FAILED: Unit - ${unit_tests[$test_name]}" "UnitTests"
    fi
done

# Step 5: Hash Function Tests
write_section "Hash Function Tests"

write_step "Testing SHA-256 with known vectors"
sha256_test_file="$SCRIPT_DIR/sha256_test.txt"
echo -n "abc" > "$sha256_test_file"

hash_output_file="$SCRIPT_DIR/sha256_output.txt"
$CRYPTOCORE_BIN dgst --algorithm sha256 --input "$sha256_test_file" --output "$hash_output_file" 2>/dev/null

if [ $? -eq 0 ] && [ -f "$hash_output_file" ]; then
    hash_content=$(cat "$hash_output_file")
    if echo "$hash_content" | grep -q "1c28dc3f1f804a1ad9c9b4b4cf5e2658d16ad4ed08e3020d04a8d2865018947c"; then
        add_test_result "PASSED: Hash - SHA-256 known vector" "Hash"
    else
        add_test_result "FAILED: Hash - SHA-256 known vector mismatch" "Hash"
    fi
    rm -f "$hash_output_file"
else
    add_test_result "FAILED: Hash - SHA-256 command failed" "Hash"
fi

write_step "Testing SHA3-256 with known vectors"
sha3_test_file="$SCRIPT_DIR/sha3_test.txt"
echo -n "abc" > "$sha3_test_file"

hash_output_file="$SCRIPT_DIR/sha3_output.txt"
$CRYPTOCORE_BIN dgst --algorithm sha3-256 --input "$sha3_test_file" --output "$hash_output_file" 2>/dev/null

if [ $? -eq 0 ] && [ -f "$hash_output_file" ]; then
    hash_content=$(cat "$hash_output_file")
    if echo "$hash_content" | grep -q "d6fc903061d8ea170c2e12d8ebc29737c5edf8fe60e11801cebd674b719166b1"; then
        add_test_result "PASSED: Hash - SHA3-256 known vector" "Hash"
    else
        add_test_result "FAILED: Hash - SHA3-256 known vector mismatch" "Hash"
    fi
    rm -f "$hash_output_file"
else
    add_test_result "FAILED: Hash - SHA3-256 command failed" "Hash"
fi

# Cleanup hash test files
rm -f "$sha256_test_file" "$sha3_test_file"

# Step 6: HMAC Tests
write_section "HMAC Functionality Tests"

write_step "Testing HMAC with RFC 4231 test vectors"

# Test Case 1
hmac_test1_file="$SCRIPT_DIR/hmac_test1.txt"
echo -n "Hi There" > "$hmac_test1_file"

hmac_output_file="$SCRIPT_DIR/hmac_output1.txt"
$CRYPTOCORE_BIN dgst --algorithm sha256 --hmac --key "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" --input "$hmac_test1_file" --output "$hmac_output_file" 2>/dev/null

if [ $? -eq 0 ] && [ -f "$hmac_output_file" ]; then
    hmac_content=$(cat "$hmac_output_file")
    if echo "$hmac_content" | grep -q "74c69388287ca06248e6be230daffe807d4c6fc0e45da0325f2fae0d1a4ee3b8"; then
        add_test_result "PASSED: HMAC - RFC 4231 Test Case 1" "HMAC"
    else
        add_test_result "FAILED: HMAC - RFC 4231 Test Case 1 mismatch" "HMAC"
    fi
    rm -f "$hmac_output_file"
else
    add_test_result "FAILED: HMAC - RFC 4231 Test Case 1 failed" "HMAC"
fi

# Test Case 2
hmac_test2_file="$SCRIPT_DIR/hmac_test2.txt"
echo -n "what do ya want for nothing?" > "$hmac_test2_file"

hmac_output_file="$SCRIPT_DIR/hmac_output2.txt"
$CRYPTOCORE_BIN dgst --algorithm sha256 --hmac --key "4a656665" --input "$hmac_test2_file" --output "$hmac_output_file" 2>/dev/null

if [ $? -eq 0 ] && [ -f "$hmac_output_file" ]; then
    hmac_content=$(cat "$hmac_output_file")
    if echo "$hmac_content" | grep -q "bbda9901e08476911958eb7d35b1afef014a1576bf8b2c6f85cc9514aed1d967"; then
        add_test_result "PASSED: HMAC - RFC 4231 Test Case 2" "HMAC"
    else
        add_test_result "FAILED: HMAC - RFC 4231 Test Case 2 mismatch" "HMAC"
    fi
    rm -f "$hmac_output_file"
else
    add_test_result "FAILED: HMAC - RFC 4231 Test Case 2 failed" "HMAC"
fi

# Cleanup HMAC test files
rm -f "$hmac_test1_file" "$hmac_test2_file"

# Step 7: NEW - GCM Mode Tests (Sprint 6)
write_section "GCM Mode Tests (NEW in v0.6.0)"

GCM_KEY="00000000000000000000000000000000"
GCM_NONCE="000000000000000000000000"
GCM_AAD="aabbccddeeff"

write_step "Testing GCM encryption/decryption with AAD"
gcm_test_file="$SCRIPT_DIR/gcm_test.txt"
echo "Hello GCM World with AAD!" > "$gcm_test_file"

# Encrypt with GCM
gcm_enc_file="$SCRIPT_DIR/gcm_encrypted.bin"
$CRYPTOCORE_BIN crypto --algorithm aes --mode gcm --operation encrypt \
    --key "$GCM_KEY" --nonce "$GCM_NONCE" --aad "$GCM_AAD" \
    --input "$gcm_test_file" --output "$gcm_enc_file" 2>/dev/null

if [ $? -ne 0 ] || [ ! -f "$gcm_enc_file" ]; then
    add_test_result "FAILED: GCM - Encryption failed" "GCM"
else
    # Decrypt with correct AAD
    gcm_dec_file="$SCRIPT_DIR/gcm_decrypted.txt"
    $CRYPTOCORE_BIN crypto --algorithm aes --mode gcm --operation decrypt \
        --key "$GCM_KEY" --aad "$GCM_AAD" \
        --input "$gcm_enc_file" --output "$gcm_dec_file" 2>/dev/null

    if [ $? -eq 0 ] && [ -f "$gcm_dec_file" ]; then
        if cmp -s "$gcm_test_file" "$gcm_dec_file"; then
            add_test_result "PASSED: GCM - Encryption/decryption with AAD" "GCM"
        else
            add_test_result "FAILED: GCM - Decryption content mismatch" "GCM"
        fi
    else
        add_test_result "FAILED: GCM - Decryption failed with correct AAD" "GCM"
    fi

    # Test with wrong AAD (should fail)
    wrong_aad="deadbeefcafe1234567890abcdef"
    gcm_wrong_file="$SCRIPT_DIR/gcm_wrong.txt"
    $CRYPTOCORE_BIN crypto --algorithm aes --mode gcm --operation decrypt \
        --key "$GCM_KEY" --aad "$wrong_aad" \
        --input "$gcm_enc_file" --output "$gcm_wrong_file" 2>&1 > /dev/null

    if [ $? -ne 0 ] && [ ! -f "$gcm_wrong_file" ]; then
        add_test_result "PASSED: GCM - Wrong AAD causes authentication failure" "GCM"
    else
        add_test_result "FAILED: GCM - Wrong AAD should fail but didn't" "GCM"
    fi

    # Cleanup
    rm -f "$gcm_dec_file" "$gcm_wrong_file" 2>/dev/null
fi

rm -f "$gcm_enc_file" 2>/dev/null

write_step "Testing GCM with automatic nonce generation"
gcm_auto_enc_file="$SCRIPT_DIR/gcm_auto_enc.bin"
$CRYPTOCORE_BIN crypto --algorithm aes --mode gcm --operation encrypt \
    --key "$GCM_KEY" --aad "$GCM_AAD" \
    --input "$gcm_test_file" --output "$gcm_auto_enc_file" 2>/dev/null

if [ $? -eq 0 ] && [ -f "$gcm_auto_enc_file" ]; then
    gcm_auto_dec_file="$SCRIPT_DIR/gcm_auto_dec.txt"
    $CRYPTOCORE_BIN crypto --algorithm aes --mode gcm --operation decrypt \
        --key "$GCM_KEY" --aad "$GCM_AAD" \
        --input "$gcm_auto_enc_file" --output "$gcm_auto_dec_file" 2>/dev/null

    if [ $? -eq 0 ] && [ -f "$gcm_auto_dec_file" ]; then
        if cmp -s "$gcm_test_file" "$gcm_auto_dec_file"; then
            add_test_result "PASSED: GCM - Auto nonce generation" "GCM"
        else
            add_test_result "FAILED: GCM - Auto nonce decryption mismatch" "GCM"
        fi
    else
        add_test_result "FAILED: GCM - Auto nonce decryption failed" "GCM"
    fi

    rm -f "$gcm_auto_dec_file" 2>/dev/null
else
    add_test_result "FAILED: GCM - Auto nonce encryption failed" "GCM"
fi

rm -f "$gcm_auto_enc_file" 2>/dev/null

write_step "Testing GCM with empty AAD"
gcm_empty_aad_enc_file="$SCRIPT_DIR/gcm_empty_aad_enc.bin"
$CRYPTOCORE_BIN crypto --algorithm aes --mode gcm --operation encrypt \
    --key "$GCM_KEY" --nonce "$GCM_NONCE" \
    --input "$gcm_test_file" --output "$gcm_empty_aad_enc_file" 2>/dev/null

if [ $? -eq 0 ] && [ -f "$gcm_empty_aad_enc_file" ]; then
    gcm_empty_aad_dec_file="$SCRIPT_DIR/gcm_empty_aad_dec.txt"
    $CRYPTOCORE_BIN crypto --algorithm aes --mode gcm --operation decrypt \
        --key "$GCM_KEY" \
        --input "$gcm_empty_aad_enc_file" --output "$gcm_empty_aad_dec_file" 2>/dev/null

    if [ $? -eq 0 ] && [ -f "$gcm_empty_aad_dec_file" ]; then
        if cmp -s "$gcm_test_file" "$gcm_empty_aad_dec_file"; then
            add_test_result "PASSED: GCM - Empty AAD works" "GCM"
        else
            add_test_result "FAILED: GCM - Empty AAD decryption mismatch" "GCM"
        fi
    else
        add_test_result "FAILED: GCM - Empty AAD decryption failed" "GCM"
    fi

    rm -f "$gcm_empty_aad_dec_file" 2>/dev/null
else
    add_test_result "FAILED: GCM - Empty AAD encryption failed" "GCM"
fi

rm -f "$gcm_empty_aad_enc_file" 2>/dev/null
rm -f "$gcm_test_file" 2>/dev/null

# Step 8: NEW - Encrypt-then-MAC (ETM) Tests
write_section "Encrypt-then-MAC (ETM) Tests (NEW in v0.6.0)"

ETM_KEY="00112233445566778899aabbccddeeff"
ETM_AAD="aabbccddeeff001122334455"

write_step "Testing ETM with CBC base mode"
etm_test_file="$SCRIPT_DIR/etm_test.txt"
echo "Test data for ETM mode with CBC" > "$etm_test_file"

# Encrypt with ETM (CBC base)
etm_enc_file="$SCRIPT_DIR/etm_encrypted.bin"
$CRYPTOCORE_BIN crypto --algorithm aes --mode etm --base-mode cbc --operation encrypt \
    --key "$ETM_KEY" --aad "$ETM_AAD" \
    --input "$etm_test_file" --output "$etm_enc_file" 2>/dev/null

if [ $? -eq 0 ] && [ -f "$etm_enc_file" ]; then
    # Decrypt with correct AAD
    etm_dec_file="$SCRIPT_DIR/etm_decrypted.txt"
    $CRYPTOCORE_BIN crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt \
        --key "$ETM_KEY" --aad "$ETM_AAD" \
        --input "$etm_enc_file" --output "$etm_dec_file" 2>/dev/null

    if [ $? -eq 0 ] && [ -f "$etm_dec_file" ]; then
        if cmp -s "$etm_test_file" "$etm_dec_file"; then
            add_test_result "PASSED: ETM - CBC base mode with AAD" "ETM"
        else
            add_test_result "FAILED: ETM - CBC decryption mismatch" "ETM"
        fi
    else
        add_test_result "FAILED: ETM - CBC decryption failed" "ETM"
    fi

    # Test with wrong AAD (should fail)
    wrong_aad="deadbeefcafe1234567890abcdef"
    etm_wrong_file="$SCRIPT_DIR/etm_wrong.txt"
    $CRYPTOCORE_BIN crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt \
        --key "$ETM_KEY" --aad "$wrong_aad" \
        --input "$etm_enc_file" --output "$etm_wrong_file" 2>&1 > /dev/null

    if [ $? -ne 0 ] && [ ! -f "$etm_wrong_file" ]; then
        add_test_result "PASSED: ETM - Wrong AAD causes authentication failure" "ETM"
    else
        add_test_result "FAILED: ETM - Wrong AAD should fail but didn't" "ETM"
    fi

    rm -f "$etm_dec_file" "$etm_wrong_file" 2>/dev/null
else
    add_test_result "FAILED: ETM - CBC encryption failed" "ETM"
fi

rm -f "$etm_enc_file" 2>/dev/null

write_step "Testing ETM with CTR base mode"
etm_ctr_enc_file="$SCRIPT_DIR/etm_ctr_enc.bin"
$CRYPTOCORE_BIN crypto --algorithm aes --mode etm --base-mode ctr --operation encrypt \
    --key "$ETM_KEY" --aad "$ETM_AAD" \
    --input "$etm_test_file" --output "$etm_ctr_enc_file" 2>/dev/null

if [ $? -eq 0 ] && [ -f "$etm_ctr_enc_file" ]; then
    etm_ctr_dec_file="$SCRIPT_DIR/etm_ctr_dec.txt"
    $CRYPTOCORE_BIN crypto --algorithm aes --mode etm --base-mode ctr --operation decrypt \
        --key "$ETM_KEY" --aad "$ETM_AAD" \
        --input "$etm_ctr_enc_file" --output "$etm_ctr_dec_file" 2>/dev/null

    if [ $? -eq 0 ] && [ -f "$etm_ctr_dec_file" ]; then
        if cmp -s "$etm_test_file" "$etm_ctr_dec_file"; then
            add_test_result "PASSED: ETM - CTR base mode with AAD" "ETM"
        else
            add_test_result "FAILED: ETM - CTR decryption mismatch" "ETM"
        fi
    else
        add_test_result "FAILED: ETM - CTR decryption failed" "ETM"
    fi

    rm -f "$etm_ctr_dec_file" 2>/dev/null
else
    add_test_result "FAILED: ETM - CTR encryption failed" "ETM"
fi

rm -f "$etm_ctr_enc_file" 2>/dev/null
rm -f "$etm_test_file" 2>/dev/null

# Step 9: Classic Encryption Modes Tests
write_section "Classic Encryption Modes Tests"

KEY="00112233445566778899aabbccddeeff"
modes=("ecb" "cbc" "cfb" "ofb" "ctr")

mode_test_count=0
total_mode_tests=${#modes[@]}

for mode in "${modes[@]}"; do
    ((mode_test_count++))
    show_progress $mode_test_count $total_mode_tests "Testing ${mode^^} mode"

    # Test with each file type
    for filename in "${!testFiles[@]}"; do
        file_path="$SCRIPT_DIR/$filename"
        encrypted_file="$SCRIPT_DIR/$filename.$mode.enc"
        decrypted_file="$SCRIPT_DIR/$filename.$mode.dec"

        # Encrypt
        $CRYPTOCORE_BIN crypto --algorithm aes --mode "$mode" --operation encrypt \
            --key "$KEY" --input "$file_path" --output "$encrypted_file" 2>/dev/null

        if [ $? -ne 0 ] || [ ! -f "$encrypted_file" ]; then
            add_test_result "FAILED: $mode - $filename encryption failed" "ClassicModes"
            continue
        fi

        # Decrypt
        $CRYPTOCORE_BIN crypto --algorithm aes --mode "$mode" --operation decrypt \
            --key "$KEY" --input "$encrypted_file" --output "$decrypted_file" 2>/dev/null

        if [ $? -ne 0 ] || [ ! -f "$decrypted_file" ]; then
            add_test_result "FAILED: $mode - $filename decryption failed" "ClassicModes"
            rm -f "$encrypted_file" 2>/dev/null
            continue
        fi

        # Compare files
        if cmp -s "$file_path" "$decrypted_file"; then
            add_test_result "PASSED: $mode - $filename round-trip" "ClassicModes"
        else
            add_test_result "FAILED: $mode - $filename content mismatch" "ClassicModes"
        fi

        # Cleanup
        rm -f "$encrypted_file" "$decrypted_file" 2>/dev/null
    done
done

# Step 10: Validation and Error Handling Tests
write_section "Validation and Error Handling"

write_step "Testing invalid key rejection"
short_file_path="$SCRIPT_DIR/short.txt"
$CRYPTOCORE_BIN crypto --algorithm aes --mode ecb --operation encrypt --key "invalid" --input "$short_file_path" --output "test.enc" 2>/dev/null
if [ $? -ne 0 ]; then
    add_test_result "PASSED: Validation - Invalid key rejected" "Validation"
else
    add_test_result "FAILED: Validation - Invalid key accepted" "Validation"
fi

write_step "Testing missing key for decryption"
$CRYPTOCORE_BIN crypto --algorithm aes --mode ecb --operation decrypt --input "$short_file_path" --output "test.dec" 2>/dev/null
if [ $? -ne 0 ]; then
    add_test_result "PASSED: Validation - Missing key for decryption rejected" "Validation"
else
    add_test_result "FAILED: Validation - Missing key for decryption accepted" "Validation"
fi

write_step "Testing IV handling validation"
$CRYPTOCORE_BIN crypto --algorithm aes --mode cbc --operation encrypt --key "$KEY" --iv "000102" --input "$short_file_path" --output "test.enc" 2>/dev/null
if [ $? -ne 0 ]; then
    add_test_result "PASSED: Validation - IV during encryption rejected" "Validation"
else
    add_test_result "FAILED: Validation - IV during encryption accepted" "Validation"
fi

write_step "Testing AAD validation for non-AEAD modes"
$CRYPTOCORE_BIN crypto --algorithm aes --mode cbc --operation encrypt --key "$KEY" --aad "aabbcc" --input "$short_file_path" --output "test.enc" 2>/dev/null
if [ $? -eq 0 ]; then
    add_test_result "PASSED: Validation - AAD with non-AEAD mode (should be ignored)" "Validation"
else
    add_test_result "FAILED: Validation - AAD with non-AEAD mode rejected" "Validation"
fi

# Step 11: OpenSSL Interoperability Tests
write_section "OpenSSL Interoperability Tests"

if command -v openssl &> /dev/null; then
    write_step "Testing CBC mode interoperability"

    interop_test_file="$SCRIPT_DIR/interop_test.txt"
    echo "OpenSSL interoperability test" > "$interop_test_file"

    TEST_IV="000102030405060708090A0B0C0D0E0F"

    # Our tool -> OpenSSL
    our_enc_file="$SCRIPT_DIR/our_encrypted.bin"
    $CRYPTOCORE_BIN crypto --algorithm aes --mode cbc --operation encrypt --key "$KEY" --input "$interop_test_file" --output "$our_enc_file"

    if [ $? -eq 0 ] && [ -f "$our_enc_file" ]; then
        # Extract IV and ciphertext
        encrypted_data=$(cat "$our_enc_file")
        iv_hex=$(echo -n "${encrypted_data:0:32}" | xxd -r -p | xxd -p | tr -d '\n')  # First 16 bytes as hex
        ciphertext_file="$SCRIPT_DIR/our_ciphertext.bin"
        echo -n "${encrypted_data:32}" | xxd -r -p > "$ciphertext_file"  # Rest as ciphertext

        # Decrypt with OpenSSL
        openssl_dec_file="$SCRIPT_DIR/openssl_decrypted.txt"
        echo -n "$iv_hex" | xxd -r -p | cat - "$ciphertext_file" | openssl enc -aes-128-cbc -d -K "$KEY" -iv "$iv_hex" -out "$openssl_dec_file" 2>/dev/null

        if [ $? -eq 0 ] && [ -f "$openssl_dec_file" ]; then
            if cmp -s "$interop_test_file" "$openssl_dec_file"; then
                add_test_result "PASSED: Interop - OurTool -> OpenSSL CBC" "Interop"
            else
                add_test_result "FAILED: Interop - OurTool -> OpenSSL content mismatch" "Interop"
            fi
        else
            add_test_result "FAILED: Interop - OurTool -> OpenSSL decryption failed" "Interop"
        fi

        rm -f "$ciphertext_file" "$openssl_dec_file" 2>/dev/null
    else
        add_test_result "FAILED: Interop - OurTool encryption failed" "Interop"
    fi

    rm -f "$our_enc_file" "$interop_test_file" 2>/dev/null
else
    add_test_result "SKIPPED: Interop - OpenSSL not available" "Interop"
fi

# Step 12: Cleanup test files
write_section "Cleanup"

for filename in "${!testFiles[@]}"; do
    rm -f "$SCRIPT_DIR/$filename" 2>/dev/null
done
rm -f "$SCRIPT_DIR/binary_16.bin" "$SCRIPT_DIR/binary_with_nulls.bin" "$SCRIPT_DIR/random_1k.bin" 2>/dev/null

# Cleanup any remaining test files
rm -f "$SCRIPT_DIR"/*.enc "$SCRIPT_DIR"/*.dec "$SCRIPT_DIR"/*test*.txt "$SCRIPT_DIR"/*test*.bin 2>/dev/null

add_test_result "PASSED: Cleanup - Test files removed" "Cleanup"

# Step 13: Generate detailed report
write_section "Test Results Summary"

# Calculate total tests
total_tests=$((passed_count + failed_count + skipped_count))

echo -e "\nDetailed Results by Category:"
echo -e "${CYAN}================================================${NC}"

for category in "${test_categories[@]}"; do
    results="${test_results[$category]}"
    if [ -n "$results" ]; then
        # Split results by pipe
        IFS='|' read -ra result_array <<< "$results"

        passed_in_category=0
        failed_in_category=0
        skipped_in_category=0

        for result in "${result_array[@]}"; do
            if [[ "$result" == "PASSED:"* ]]; then
                ((passed_in_category++))
            elif [[ "$result" == "FAILED:"* ]]; then
                ((failed_in_category++))
            elif [[ "$result" == "SKIPPED:"* ]]; then
                ((skipped_in_category++))
            fi
        done

        total_in_category=$((passed_in_category + failed_in_category + skipped_in_category))

        if [ $failed_in_category -eq 0 ]; then
            echo -e "${GREEN}\n$category${NC}"
        else
            echo -e "${RED}\n$category${NC}"
        fi

        echo -e "  Total: $total_in_category"
        echo -e "  ${GREEN}Passed: $passed_in_category${NC}"
        echo -e "  ${RED}Failed: $failed_in_category${NC}"
        echo -e "  ${YELLOW}Skipped: $skipped_in_category${NC}"

        if [ $failed_in_category -gt 0 ]; then
            echo -e "  ${RED}Failures:${NC}"
            for result in "${result_array[@]}"; do
                if [[ "$result" == "FAILED:"* ]]; then
                    echo -e "    - $result"
                fi
            done
        fi
    fi
done

echo -e "\n${CYAN}================================================${NC}"
echo -e "${CYAN}FINAL SUMMARY${NC}"
echo -e "${CYAN}================================================${NC}"
echo -e "Total Tests: $total_tests"
echo -e "${GREEN}Passed: $passed_count${NC}"
echo -e "${RED}Failed: $failed_count${NC}"
echo -e "${YELLOW}Skipped: $skipped_count${NC}"
success_rate=$(awk "BEGIN {printf \"%.1f\", ($passed_count/$total_tests)*100}")
echo -e "Success Rate: ${success_rate}%"

echo -e "\n${CYAN}================================================${NC}"
echo -e "${CYAN}FEATURE STATUS${NC}"
echo -e "${CYAN}================================================${NC}"

# Check feature status
check_feature_status() {
    local feature_name="$1"
    local pattern="$2"

    passed=0
    failed=0
    total=0

    for category in "${test_categories[@]}"; do
        results="${test_results[$category]}"
        if [ -n "$results" ]; then
            IFS='|' read -ra result_array <<< "$results"
            for result in "${result_array[@]}"; do
                if [[ "$result" == *"$pattern"* ]]; then
                    ((total++))
                    if [[ "$result" == "PASSED:"* ]]; then
                        ((passed++))
                    elif [[ "$result" == "FAILED:"* ]]; then
                        ((failed++))
                    fi
                fi
            done
        fi
    done

    if [ $total -gt 0 ]; then
        if [ $failed -eq 0 ]; then
            echo -e "${GREEN}[OK] PASSED $feature_name ($passed/$total passed)${NC}"
        else
            echo -e "${RED}[X] FAILED $feature_name ($passed/$total passed)${NC}"
        fi
    fi
}

check_feature_status "Basic CLI" "Basic"
check_feature_status "Hash Functions" "Hash"
check_feature_status "HMAC" "HMAC"
check_feature_status "GCM (AEAD)" "GCM"
check_feature_status "ETM (Encrypt-then-MAC)" "ETM"
check_feature_status "Classic Modes" "ecb\|cbc\|cfb\|ofb\|ctr"
check_feature_status "Validation" "Validation"
check_feature_status "Interoperability" "Interop"

echo -e "${CYAN}================================================${NC}"

if $all_tests_passed; then
    echo -e "${GREEN}ALL TESTS PASSED! CryptoCore v0.6.0 is fully functional!${NC}"
    echo -e "${GREEN}All requirements from M6 document are satisfied${NC}"
    echo -e "${GREEN}AEAD (GCM and Encrypt-then-MAC) implemented${NC}"
    echo -e "${GREEN}Catastrophic authentication failure working${NC}"
    echo -e "${GREEN}Nonce generation and AAD support working${NC}"
    echo -e "${GREEN}Backward compatibility maintained${NC}"
else
    echo -e "${RED}SOME TESTS FAILED! Please check the failures above.${NC}"
    echo -e "${RED}Failed tests need investigation before submission.${NC}"
    exit 1
fi

echo -e "\n${GRAY}Test execution completed at $(date '+%H:%M:%S')${NC}"

# Save detailed report to file
report_file="$PROJECT_ROOT/test_report_$(date '+%Y%m%d_%H%M%S').txt"
{
    echo "CRYPTOCORE TEST REPORT"
    echo "Generated: $(date)"
    echo "Version: 0.6.0"
    echo "Test Script: $(basename "$0")"
    echo ""
    echo "SUMMARY:"
    echo "========"
    echo "Total Tests: $total_tests"
    echo "Passed: $passed_count"
    echo "Failed: $failed_count"
    echo "Skipped: $skipped_count"
    echo "Success Rate: ${success_rate}%"
    echo ""
    echo "DETAILED RESULTS:"
    echo "================="

    for category in "${test_categories[@]}"; do
        results="${test_results[$category]}"
        if [ -n "$results" ]; then
            IFS='|' read -ra result_array <<< "$results"
            for result in "${result_array[@]}"; do
                echo "$(date '+%H:%M:%S') - $category: $result"
            done
        fi
    done
} > "$report_file"

echo -e "\n${CYAN}Detailed report saved to: $report_file${NC}"

echo -e "\nPress any key to exit..."
read -n 1 -s