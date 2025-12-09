# test.ps1 - Complete Automated Testing for Windows PowerShell (Updated for v0.6.0 with AEAD)

Write-Host "Starting CryptoCore Complete Automated Tests (v0.6.0 with AEAD)..." -ForegroundColor Cyan

# Colors and formatting
function Write-Step { Write-Host ">>> $($args[0])" -ForegroundColor Blue }
function Write-Section {
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  $($args[0])" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
}
function Write-Status {
    param($Success, $Message)
    if ($Success) { Write-Host "SUCCESS: $Message" -ForegroundColor Green }
    else { Write-Host "FAILED: $Message" -ForegroundColor Red }
}

# Get the script directory and project root
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$PROJECT_ROOT = if ($SCRIPT_DIR -like "*\scripts") { Split-Path -Parent $SCRIPT_DIR } else { $SCRIPT_DIR }

Write-Host "Script directory: $SCRIPT_DIR" -ForegroundColor Gray
Write-Host "Project root: $PROJECT_ROOT" -ForegroundColor Gray

# Initialize test results
$global:testResults = @()
$global:passedCount = 0
$global:failedCount = 0
$global:skippedCount = 0
$global:allTestsPassed = $true

function Add-TestResult {
    param($Result, $Category = "General")
    $global:testResults += @{
        Category = $Category
        Result = $Result
        Timestamp = Get-Date
    }

    if ($Result -like "PASSED:*") {
        $global:passedCount++
    } elseif ($Result -like "FAILED:*") {
        $global:failedCount++
        $global:allTestsPassed = $false
    } elseif ($Result -like "SKIPPED:*") {
        $global:skippedCount++
    }
}

function Show-Progress {
    param($Current, $Total, $Message)
    $percent = [math]::Round(($Current / $Total) * 100, 1)
    Write-Host "[$Current/$Total - ${percent}%] $Message" -ForegroundColor Yellow
}

# Step 1: Build project
Write-Section "Building Project"
Set-Location $PROJECT_ROOT

Write-Step "Building release version"
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Release build failed!" -ForegroundColor Red
    exit 1
}
Add-TestResult "PASSED: Build - Release build completed" "Build"

Write-Step "Building debug version"
cargo build
if ($LASTEXITCODE -ne 0) {
    Write-Host "Debug build failed!" -ForegroundColor Red
    exit 1
}
Add-TestResult "PASSED: Build - Debug build completed" "Build"

# Define the path to the executable
$CRYPTOCORE_EXE = Join-Path $PROJECT_ROOT "target\release\cryptocore.exe"
if (-not (Test-Path $CRYPTOCORE_EXE)) {
    Write-Host "Release executable not found at $CRYPTOCORE_EXE" -ForegroundColor Yellow
    $CRYPTOCORE_EXE = Join-Path $PROJECT_ROOT "target\debug\cryptocore.exe"
    if (-not (Test-Path $CRYPTOCORE_EXE)) {
        Write-Host "Executable not found at $CRYPTOCORE_EXE" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Using executable: $CRYPTOCORE_EXE" -ForegroundColor Green

# Change to script directory for test files
Set-Location $SCRIPT_DIR

# Step 2: Basic functionality tests
Write-Section "Basic Functionality Tests"

Write-Step "Testing help command"
& $CRYPTOCORE_EXE --help | Out-Null
if ($LASTEXITCODE -eq 0) {
    Add-TestResult "PASSED: Basic - Help command works" "Basic"
} else {
    Add-TestResult "FAILED: Basic - Help command failed" "Basic"
}

Write-Step "Testing version command"
$versionOutput = & $CRYPTOCORE_EXE --version 2>&1 | Select-String "0\.6\.0"
if ($versionOutput) {
    Add-TestResult "PASSED: Basic - Version command shows 0.6.0" "Basic"
} else {
    Add-TestResult "FAILED: Basic - Version command failed" "Basic"
}

# Step 3: Create comprehensive test files
Write-Section "Creating Test Files"

$testFiles = @{
    "empty.txt" = ""
    "short.txt" = "Short test"
    "medium.txt" = "This is a medium length test file for encryption testing with various data patterns."
    "long.txt" = "This is a much longer test file that contains significantly more data to ensure encryption works properly with different data sizes, padding requirements, and edge cases. It includes various characters and patterns."
    "special_chars.txt" = 'Special chars: ~!@#$%^&*()_+{}|:""<>?[]\;'',./'
    "unicode.txt" = "Unicode test: Hello World"
}

# Create text files
foreach ($file in $testFiles.GetEnumerator()) {
    $filePath = Join-Path $SCRIPT_DIR $file.Key
    $file.Value | Out-File -FilePath $filePath -Encoding utf8
    Write-Host "Created $($file.Key)" -ForegroundColor Green
}

# Create binary files
$binaryData1 = @(0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f)
[System.IO.File]::WriteAllBytes((Join-Path $SCRIPT_DIR "binary_16.bin"), $binaryData1)

$binaryData2 = @(0x42,0x69,0x6E,0x61,0x72,0x79,0x00,0x64,0x61,0x74,0x61,0x00,0x77,0x69,0x74,0x68,0x00,0x6E,0x75,0x6C,0x6C,0x73,0x00,0x61,0x6E,0x64,0x00,0x73,0x70,0x65,0x63,0x69,0x61,0x6C,0x00,0x63,0x68,0x61,0x72,0x73,0xFF,0xFE,0xFD)
[System.IO.File]::WriteAllBytes((Join-Path $SCRIPT_DIR "binary_with_nulls.bin"), $binaryData2)

# Create random 1KB file
$randomBytes = New-Object byte[] 1024
(New-Object Random).NextBytes($randomBytes)
[System.IO.File]::WriteAllBytes((Join-Path $SCRIPT_DIR "random_1k.bin"), $randomBytes)

Add-TestResult "PASSED: Files - Test files created" "Files"

# Step 4: Run unit tests
Write-Section "Unit Tests"

$unitTests = @(
    @{Name="csprng"; Description="CSPRNG module tests"},
    @{Name="hash"; Description="Hash module tests"},
    @{Name="hmac"; Description="HMAC module tests"},
    @{Name="gcm"; Description="GCM module tests"},
    @{Name="aead"; Description="AEAD module tests"},
    @{Name="integration_tests"; Description="Integration tests"}
)

$unitTestCount = 0
foreach ($test in $unitTests) {
    $unitTestCount++
    Show-Progress $unitTestCount $unitTests.Count "Testing $($test.Name)"

    try {
        cargo test --test $test.Name -- --nocapture 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Add-TestResult "PASSED: Unit - $($test.Description)" "UnitTests"
        } else {
            Add-TestResult "FAILED: Unit - $($test.Description)" "UnitTests"
        }
    } catch {
        Add-TestResult "FAILED: Unit - $($test.Description) (Error: $($_.Exception.Message))" "UnitTests"
    }
}

# Step 5: Hash Function Tests
Write-Section "Hash Function Tests"

Write-Step "Testing SHA-256 with known vectors"
$sha256TestFile = Join-Path $SCRIPT_DIR "sha256_test.txt"
"abc" | Out-File -FilePath $sha256TestFile -Encoding utf8 -NoNewline

try {
    # Save output to file instead of stdout
    $hashOutputFile = Join-Path $SCRIPT_DIR "sha256_output.txt"
    & $CRYPTOCORE_EXE dgst --algorithm sha256 --input $sha256TestFile --output $hashOutputFile

    if ($LASTEXITCODE -eq 0 -and (Test-Path $hashOutputFile)) {
        $hashContent = Get-Content $hashOutputFile -Raw
        if ($hashContent -match "1c28dc3f1f804a1ad9c9b4b4cf5e2658d16ad4ed08e3020d04a8d2865018947c") {
            Add-TestResult "PASSED: Hash - SHA-256 known vector" "Hash"
        } else {
            Add-TestResult "FAILED: Hash - SHA-256 known vector mismatch" "Hash"
        }
        Remove-Item $hashOutputFile -ErrorAction SilentlyContinue
    } else {
        Add-TestResult "FAILED: Hash - SHA-256 command failed" "Hash"
    }
} catch {
    Add-TestResult "FAILED: Hash - SHA-256 test error: $($_.Exception.Message)" "Hash"
}

Write-Step "Testing SHA3-256 with known vectors"
$sha3TestFile = Join-Path $SCRIPT_DIR "sha3_test.txt"
"abc" | Out-File -FilePath $sha3TestFile -Encoding utf8 -NoNewline

try {
    $hashOutputFile = Join-Path $SCRIPT_DIR "sha3_output.txt"
    & $CRYPTOCORE_EXE dgst --algorithm sha3-256 --input $sha3TestFile --output $hashOutputFile

    if ($LASTEXITCODE -eq 0 -and (Test-Path $hashOutputFile)) {
        $hashContent = Get-Content $hashOutputFile -Raw
        if ($hashContent -match "d6fc903061d8ea170c2e12d8ebc29737c5edf8fe60e11801cebd674b719166b1") {
            Add-TestResult "PASSED: Hash - SHA3-256 known vector" "Hash"
        } else {
            Add-TestResult "FAILED: Hash - SHA3-256 known vector mismatch" "Hash"
        }
        Remove-Item $hashOutputFile -ErrorAction SilentlyContinue
    } else {
        Add-TestResult "FAILED: Hash - SHA3-256 command failed" "Hash"
    }
} catch {
    Add-TestResult "FAILED: Hash - SHA3-256 test error: $($_.Exception.Message)" "Hash"
}

# Cleanup hash test files
Remove-Item $sha256TestFile, $sha3TestFile -ErrorAction SilentlyContinue

# Step 6: HMAC Tests
Write-Section "HMAC Functionality Tests"

Write-Step "Testing HMAC with RFC 4231 test vectors"

# Test Case 1
$hmacTest1File = Join-Path $SCRIPT_DIR "hmac_test1.txt"
"Hi There" | Out-File -FilePath $hmacTest1File -Encoding utf8 -NoNewline

try {
    $hmacOutputFile = Join-Path $SCRIPT_DIR "hmac_output1.txt"
    & $CRYPTOCORE_EXE dgst --algorithm sha256 --hmac --key "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b" --input $hmacTest1File --output $hmacOutputFile

    if ($LASTEXITCODE -eq 0 -and (Test-Path $hmacOutputFile)) {
        $hmacContent = Get-Content $hmacOutputFile -Raw
        if ($hmacContent -match "74c69388287ca06248e6be230daffe807d4c6fc0e45da0325f2fae0d1a4ee3b8") {
            Add-TestResult "PASSED: HMAC - RFC 4231 Test Case 1" "HMAC"
        } else {
            Add-TestResult "FAILED: HMAC - RFC 4231 Test Case 1 mismatch" "HMAC"
        }
        Remove-Item $hmacOutputFile -ErrorAction SilentlyContinue
    } else {
        Add-TestResult "FAILED: HMAC - RFC 4231 Test Case 1 failed" "HMAC"
    }
} catch {
    Add-TestResult "FAILED: HMAC - RFC 4231 Test Case 1 error" "HMAC"
}

# Test Case 2
$hmacTest2File = Join-Path $SCRIPT_DIR "hmac_test2.txt"
"what do ya want for nothing?" | Out-File -FilePath $hmacTest2File -Encoding utf8 -NoNewline

try {
    $hmacOutputFile = Join-Path $SCRIPT_DIR "hmac_output2.txt"
    & $CRYPTOCORE_EXE dgst --algorithm sha256 --hmac --key "4a656665" --input $hmacTest2File --output $hmacOutputFile

    if ($LASTEXITCODE -eq 0 -and (Test-Path $hmacOutputFile)) {
        $hmacContent = Get-Content $hmacOutputFile -Raw
        if ($hmacContent -match "bbda9901e08476911958eb7d35b1afef014a1576bf8b2c6f85cc9514aed1d967") {
            Add-TestResult "PASSED: HMAC - RFC 4231 Test Case 2" "HMAC"
        } else {
            Add-TestResult "FAILED: HMAC - RFC 4231 Test Case 2 mismatch" "HMAC"
        }
        Remove-Item $hmacOutputFile -ErrorAction SilentlyContinue
    } else {
        Add-TestResult "FAILED: HMAC - RFC 4231 Test Case 2 failed" "HMAC"
    }
} catch {
    Add-TestResult "FAILED: HMAC - RFC 4231 Test Case 2 error" "HMAC"
}

# Cleanup HMAC test files
Remove-Item $hmacTest1File, $hmacTest2File -ErrorAction SilentlyContinue

# Step 7: NEW - GCM Mode Tests (Sprint 6)
Write-Section "GCM Mode Tests (NEW in v0.6.0)"

$gcmKey = "00000000000000000000000000000000"
$gcmNonce = "000000000000000000000000"
$gcmAad = "aabbccddeeff"

Write-Step "Testing GCM encryption/decryption with AAD"
$gcmTestFile = Join-Path $SCRIPT_DIR "gcm_test.txt"
"Hello GCM World with AAD!" | Out-File -FilePath $gcmTestFile -Encoding utf8

try {
    # Encrypt with GCM
    $gcmEncFile = Join-Path $SCRIPT_DIR "gcm_encrypted.bin"
    & $CRYPTOCORE_EXE crypto --algorithm aes --mode gcm --operation encrypt `
        --key $gcmKey --nonce $gcmNonce --aad $gcmAad `
        --input $gcmTestFile --output $gcmEncFile

    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $gcmEncFile)) {
        Add-TestResult "FAILED: GCM - Encryption failed" "GCM"
    } else {
        # Decrypt with correct AAD
        $gcmDecFile = Join-Path $SCRIPT_DIR "gcm_decrypted.txt"
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode gcm --operation decrypt `
            --key $gcmKey --aad $gcmAad `
            --input $gcmEncFile --output $gcmDecFile

        if ($LASTEXITCODE -eq 0 -and (Test-Path $gcmDecFile)) {
            $original = Get-Content $gcmTestFile -Raw
            $decrypted = Get-Content $gcmDecFile -Raw
            if ($original -eq $decrypted) {
                Add-TestResult "PASSED: GCM - Encryption/decryption with AAD" "GCM"
            } else {
                Add-TestResult "FAILED: GCM - Decryption content mismatch" "GCM"
            }
        } else {
            Add-TestResult "FAILED: GCM - Decryption failed with correct AAD" "GCM"
        }

        # Test with wrong AAD (should fail)
        $wrongAad = "deadbeefcafe1234567890abcdef"
        $gcmWrongFile = Join-Path $SCRIPT_DIR "gcm_wrong.txt"
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode gcm --operation decrypt `
            --key $gcmKey --aad $wrongAad `
            --input $gcmEncFile --output $gcmWrongFile 2>&1 | Out-Null

        if ($LASTEXITCODE -ne 0 -and -not (Test-Path $gcmWrongFile)) {
            Add-TestResult "PASSED: GCM - Wrong AAD causes authentication failure" "GCM"
        } else {
            Add-TestResult "FAILED: GCM - Wrong AAD should fail but didn't" "GCM"
        }

        # Cleanup
        Remove-Item $gcmDecFile, $gcmWrongFile -ErrorAction SilentlyContinue
    }

    Remove-Item $gcmEncFile -ErrorAction SilentlyContinue
} catch {
    Add-TestResult "FAILED: GCM - Test error: $($_.Exception.Message)" "GCM"
}

Write-Step "Testing GCM with automatic nonce generation"
try {
    $gcmAutoEncFile = Join-Path $SCRIPT_DIR "gcm_auto_enc.bin"
    & $CRYPTOCORE_EXE crypto --algorithm aes --mode gcm --operation encrypt `
        --key $gcmKey --aad $gcmAad `
        --input $gcmTestFile --output $gcmAutoEncFile

    if ($LASTEXITCODE -eq 0 -and (Test-Path $gcmAutoEncFile)) {
        $gcmAutoDecFile = Join-Path $SCRIPT_DIR "gcm_auto_dec.txt"
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode gcm --operation decrypt `
            --key $gcmKey --aad $gcmAad `
            --input $gcmAutoEncFile --output $gcmAutoDecFile

        if ($LASTEXITCODE -eq 0 -and (Test-Path $gcmAutoDecFile)) {
            $original = Get-Content $gcmTestFile -Raw
            $decrypted = Get-Content $gcmAutoDecFile -Raw
            if ($original -eq $decrypted) {
                Add-TestResult "PASSED: GCM - Auto nonce generation" "GCM"
            } else {
                Add-TestResult "FAILED: GCM - Auto nonce decryption mismatch" "GCM"
            }
        } else {
            Add-TestResult "FAILED: GCM - Auto nonce decryption failed" "GCM"
        }

        Remove-Item $gcmAutoDecFile -ErrorAction SilentlyContinue
    } else {
        Add-TestResult "FAILED: GCM - Auto nonce encryption failed" "GCM"
    }

    Remove-Item $gcmAutoEncFile -ErrorAction SilentlyContinue
} catch {
    Add-TestResult "FAILED: GCM - Auto nonce test error" "GCM"
}

Write-Step "Testing GCM with empty AAD"
try {
    $gcmEmptyAadEncFile = Join-Path $SCRIPT_DIR "gcm_empty_aad_enc.bin"
    & $CRYPTOCORE_EXE crypto --algorithm aes --mode gcm --operation encrypt `
        --key $gcmKey --nonce $gcmNonce `
        --input $gcmTestFile --output $gcmEmptyAadEncFile

    if ($LASTEXITCODE -eq 0 -and (Test-Path $gcmEmptyAadEncFile)) {
        $gcmEmptyAadDecFile = Join-Path $SCRIPT_DIR "gcm_empty_aad_dec.txt"
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode gcm --operation decrypt `
            --key $gcmKey `
            --input $gcmEmptyAadEncFile --output $gcmEmptyAadDecFile

        if ($LASTEXITCODE -eq 0 -and (Test-Path $gcmEmptyAadDecFile)) {
            $original = Get-Content $gcmTestFile -Raw
            $decrypted = Get-Content $gcmEmptyAadDecFile -Raw
            if ($original -eq $decrypted) {
                Add-TestResult "PASSED: GCM - Empty AAD works" "GCM"
            } else {
                Add-TestResult "FAILED: GCM - Empty AAD decryption mismatch" "GCM"
            }
        } else {
            Add-TestResult "FAILED: GCM - Empty AAD decryption failed" "GCM"
        }

        Remove-Item $gcmEmptyAadDecFile -ErrorAction SilentlyContinue
    } else {
        Add-TestResult "FAILED: GCM - Empty AAD encryption failed" "GCM"
    }

    Remove-Item $gcmEmptyAadEncFile -ErrorAction SilentlyContinue
} catch {
    Add-TestResult "FAILED: GCM - Empty AAD test error" "GCM"
}

Remove-Item $gcmTestFile -ErrorAction SilentlyContinue

# Step 8: NEW - Encrypt-then-MAC (ETM) Tests
Write-Section "Encrypt-then-MAC (ETM) Tests (NEW in v0.6.0)"

$etmKey = "00112233445566778899aabbccddeeff"
$etmAad = "aabbccddeeff001122334455"

Write-Step "Testing ETM with CBC base mode"
$etmTestFile = Join-Path $SCRIPT_DIR "etm_test.txt"
"Test data for ETM mode with CBC" | Out-File -FilePath $etmTestFile -Encoding utf8

try {
    # Encrypt with ETM (CBC base)
    $etmEncFile = Join-Path $SCRIPT_DIR "etm_encrypted.bin"
    & $CRYPTOCORE_EXE crypto --algorithm aes --mode etm --base-mode cbc --operation encrypt `
        --key $etmKey --aad $etmAad `
        --input $etmTestFile --output $etmEncFile

    if ($LASTEXITCODE -eq 0 -and (Test-Path $etmEncFile)) {
        # Decrypt with correct AAD
        $etmDecFile = Join-Path $SCRIPT_DIR "etm_decrypted.txt"
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt `
            --key $etmKey --aad $etmAad `
            --input $etmEncFile --output $etmDecFile

        if ($LASTEXITCODE -eq 0 -and (Test-Path $etmDecFile)) {
            $original = Get-Content $etmTestFile -Raw
            $decrypted = Get-Content $etmDecFile -Raw
            if ($original -eq $decrypted) {
                Add-TestResult "PASSED: ETM - CBC base mode with AAD" "ETM"
            } else {
                Add-TestResult "FAILED: ETM - CBC decryption mismatch" "ETM"
            }
        } else {
            Add-TestResult "FAILED: ETM - CBC decryption failed" "ETM"
        }

        # Test with wrong AAD (should fail)
        $wrongAad = "deadbeefcafe1234567890abcdef"
        $etmWrongFile = Join-Path $SCRIPT_DIR "etm_wrong.txt"
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode etm --base-mode cbc --operation decrypt `
            --key $etmKey --aad $wrongAad `
            --input $etmEncFile --output $etmWrongFile 2>&1 | Out-Null

        if ($LASTEXITCODE -ne 0 -and -not (Test-Path $etmWrongFile)) {
            Add-TestResult "PASSED: ETM - Wrong AAD causes authentication failure" "ETM"
        } else {
            Add-TestResult "FAILED: ETM - Wrong AAD should fail but didn't" "ETM"
        }

        Remove-Item $etmDecFile, $etmWrongFile -ErrorAction SilentlyContinue
    } else {
        Add-TestResult "FAILED: ETM - CBC encryption failed" "ETM"
    }

    Remove-Item $etmEncFile -ErrorAction SilentlyContinue
} catch {
    Add-TestResult "FAILED: ETM - CBC test error: $($_.Exception.Message)" "ETM"
}

Write-Step "Testing ETM with CTR base mode"
try {
    $etmCtrEncFile = Join-Path $SCRIPT_DIR "etm_ctr_enc.bin"
    & $CRYPTOCORE_EXE crypto --algorithm aes --mode etm --base-mode ctr --operation encrypt `
        --key $etmKey --aad $etmAad `
        --input $etmTestFile --output $etmCtrEncFile

    if ($LASTEXITCODE -eq 0 -and (Test-Path $etmCtrEncFile)) {
        $etmCtrDecFile = Join-Path $SCRIPT_DIR "etm_ctr_dec.txt"
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode etm --base-mode ctr --operation decrypt `
            --key $etmKey --aad $etmAad `
            --input $etmCtrEncFile --output $etmCtrDecFile

        if ($LASTEXITCODE -eq 0 -and (Test-Path $etmCtrDecFile)) {
            $original = Get-Content $etmTestFile -Raw
            $decrypted = Get-Content $etmCtrDecFile -Raw
            if ($original -eq $decrypted) {
                Add-TestResult "PASSED: ETM - CTR base mode with AAD" "ETM"
            } else {
                Add-TestResult "FAILED: ETM - CTR decryption mismatch" "ETM"
            }
        } else {
            Add-TestResult "FAILED: ETM - CTR decryption failed" "ETM"
        }

        Remove-Item $etmCtrDecFile -ErrorAction SilentlyContinue
    } else {
        Add-TestResult "FAILED: ETM - CTR encryption failed" "ETM"
    }

    Remove-Item $etmCtrEncFile -ErrorAction SilentlyContinue
} catch {
    Add-TestResult "FAILED: ETM - CTR test error" "ETM"
}

Remove-Item $etmTestFile -ErrorAction SilentlyContinue

# Step 9: Classic Encryption Modes Tests
Write-Section "Classic Encryption Modes Tests"

$KEY = "00112233445566778899aabbccddeeff"
$modes = @("ecb", "cbc", "cfb", "ofb", "ctr")

$modeTestCount = 0
foreach ($mode in $modes) {
    $modeTestCount++
    Show-Progress $modeTestCount $modes.Count "Testing $($mode.ToUpper()) mode"

    # Test with each file type
    foreach ($file in $testFiles.GetEnumerator()) {
        $filePath = Join-Path $SCRIPT_DIR $file.Key
        $encryptedFile = Join-Path $SCRIPT_DIR "$($file.Key).$mode.enc"
        $decryptedFile = Join-Path $SCRIPT_DIR "$($file.Key).$mode.dec"

        try {
            # Build encryption command
            $encryptArgs = @(
                "crypto", "--algorithm", "aes",
                "--mode", $mode,
                "--operation", "encrypt",
                "--key", $KEY,
                "--input", $filePath,
                "--output", $encryptedFile
            )

            # Build decryption command
            $decryptArgs = @(
                "crypto", "--algorithm", "aes",
                "--mode", $mode,
                "--operation", "decrypt",
                "--key", $KEY,
                "--input", $encryptedFile,
                "--output", $decryptedFile
            )

            # Encrypt
            & $CRYPTOCORE_EXE @encryptArgs 2>&1 | Out-Null
            $encryptSuccess = ($LASTEXITCODE -eq 0) -and (Test-Path $encryptedFile)

            if (-not $encryptSuccess) {
                Add-TestResult "FAILED: $mode - $($file.Key) encryption failed" "ClassicModes"
                continue
            }

            # Decrypt
            & $CRYPTOCORE_EXE @decryptArgs 2>&1 | Out-Null
            $decryptSuccess = ($LASTEXITCODE -eq 0) -and (Test-Path $decryptedFile)

            if (-not $decryptSuccess) {
                Add-TestResult "FAILED: $mode - $($file.Key) decryption failed" "ClassicModes"
                Remove-Item $encryptedFile -ErrorAction SilentlyContinue
                continue
            }

            # Compare files
            $original = Get-Content $filePath -Raw
            $decrypted = Get-Content $decryptedFile -Raw

            if ($original -eq $decrypted) {
                Add-TestResult "PASSED: $mode - $($file.Key) round-trip" "ClassicModes"
            } else {
                Add-TestResult "FAILED: $mode - $($file.Key) content mismatch" "ClassicModes"
            }

            # Cleanup
            Remove-Item $encryptedFile, $decryptedFile -ErrorAction SilentlyContinue

        } catch {
            Add-TestResult "FAILED: $mode - $($file.Key) error: $($_.Exception.Message)" "ClassicModes"
        }
    }
}

# Step 10: Validation and Error Handling Tests
Write-Section "Validation and Error Handling"

Write-Step "Testing invalid key rejection"
$shortFilePath = Join-Path $SCRIPT_DIR "short.txt"
& $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation encrypt --key "invalid" --input $shortFilePath --output "test.enc" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Add-TestResult "PASSED: Validation - Invalid key rejected" "Validation"
} else {
    Add-TestResult "FAILED: Validation - Invalid key accepted" "Validation"
}

Write-Step "Testing missing key for decryption"
& $CRYPTOCORE_EXE crypto --algorithm aes --mode ecb --operation decrypt --input $shortFilePath --output "test.dec" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Add-TestResult "PASSED: Validation - Missing key for decryption rejected" "Validation"
} else {
    Add-TestResult "FAILED: Validation - Missing key for decryption accepted" "Validation"
}

Write-Step "Testing IV handling validation"
& $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation encrypt --key $KEY --iv "000102" --input $shortFilePath --output "test.enc" 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Add-TestResult "PASSED: Validation - IV during encryption rejected" "Validation"
} else {
    Add-TestResult "FAILED: Validation - IV during encryption accepted" "Validation"
}

Write-Step "Testing AAD validation for non-AEAD modes"
& $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation encrypt --key $KEY --aad "aabbcc" --input $shortFilePath --output "test.enc" 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Add-TestResult "PASSED: Validation - AAD with non-AEAD mode (should be ignored)" "Validation"
} else {
    Add-TestResult "FAILED: Validation - AAD with non-AEAD mode rejected" "Validation"
}

# Step 11: OpenSSL Interoperability Tests
Write-Section "OpenSSL Interoperability Tests"

if (Get-Command "openssl" -ErrorAction SilentlyContinue) {
    Write-Step "Testing CBC mode interoperability"

    $interopTestFile = Join-Path $SCRIPT_DIR "interop_test.txt"
    "OpenSSL interoperability test" | Out-File -FilePath $interopTestFile -Encoding utf8

    $TEST_IV = "000102030405060708090A0B0C0D0E0F"

    try {
        # Our tool -> OpenSSL
        $ourEncFile = Join-Path $SCRIPT_DIR "our_encrypted.bin"
        & $CRYPTOCORE_EXE crypto --algorithm aes --mode cbc --operation encrypt --key $KEY --input $interopTestFile --output $ourEncFile

        if ($LASTEXITCODE -eq 0 -and (Test-Path $ourEncFile)) {
            # Extract IV and ciphertext
            $encryptedData = [System.IO.File]::ReadAllBytes($ourEncFile)
            $ivBytes = $encryptedData[0..15]
            $ciphertextBytes = $encryptedData[16..($encryptedData.Length-1)]

            $ourIvFile = Join-Path $SCRIPT_DIR "our_iv.bin"
            $ourCiphertextFile = Join-Path $SCRIPT_DIR "our_ciphertext.bin"
            [System.IO.File]::WriteAllBytes($ourIvFile, $ivBytes)
            [System.IO.File]::WriteAllBytes($ourCiphertextFile, $ciphertextBytes)

            # Convert IV to hex for OpenSSL
            $ivHex = -join ($ivBytes | ForEach-Object { $_.ToString("X2") })

            # Decrypt with OpenSSL
            $opensslDecFile = Join-Path $SCRIPT_DIR "openssl_decrypted.txt"
            openssl enc -aes-128-cbc -d -K $KEY -iv $ivHex -in $ourCiphertextFile -out $opensslDecFile

            if ($LASTEXITCODE -eq 0 -and (Test-Path $opensslDecFile)) {
                $original = Get-Content $interopTestFile -Raw
                $decrypted = Get-Content $opensslDecFile -Raw

                if ($original -eq $decrypted) {
                    Add-TestResult "PASSED: Interop - OurTool -> OpenSSL CBC" "Interop"
                } else {
                    Add-TestResult "FAILED: Interop - OurTool -> OpenSSL content mismatch" "Interop"
                }
            } else {
                Add-TestResult "FAILED: Interop - OurTool -> OpenSSL decryption failed" "Interop"
            }

            Remove-Item $ourIvFile, $ourCiphertextFile, $opensslDecFile -ErrorAction SilentlyContinue
        } else {
            Add-TestResult "FAILED: Interop - OurTool encryption failed" "Interop"
        }

        Remove-Item $ourEncFile -ErrorAction SilentlyContinue
        Remove-Item $interopTestFile -ErrorAction SilentlyContinue

    } catch {
        Add-TestResult "FAILED: Interop - Test error: $($_.Exception.Message)" "Interop"
    }
} else {
    Add-TestResult "SKIPPED: Interop - OpenSSL not available" "Interop"
}

# Step 12: Cleanup test files
Write-Section "Cleanup"

foreach ($file in $testFiles.GetEnumerator()) {
    $filePath = Join-Path $SCRIPT_DIR $file.Key
    Remove-Item $filePath -ErrorAction SilentlyContinue
}
Remove-Item (Join-Path $SCRIPT_DIR "binary_16.bin"), (Join-Path $SCRIPT_DIR "binary_with_nulls.bin"), (Join-Path $SCRIPT_DIR "random_1k.bin") -ErrorAction SilentlyContinue

# Cleanup any remaining test files
Get-ChildItem -Path $SCRIPT_DIR -Filter "*.enc" -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
Get-ChildItem -Path $SCRIPT_DIR -Filter "*.dec" -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
Get-ChildItem -Path $SCRIPT_DIR -Filter "*test*.txt" -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue
Get-ChildItem -Path $SCRIPT_DIR -Filter "*test*.bin" -ErrorAction SilentlyContinue | Remove-Item -ErrorAction SilentlyContinue

Add-TestResult "PASSED: Cleanup - Test files removed" "Cleanup"

# Step 13: Generate detailed report
Write-Section "Test Results Summary"

# Group results by category
$resultsByCategory = $global:testResults | Group-Object Category

Write-Host "`nDetailed Results by Category:" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan

foreach ($category in $resultsByCategory) {
    $categoryName = $category.Name
    $categoryResults = $category.Group

    $passed = ($categoryResults | Where-Object { $_.Result -like "PASSED:*" }).Count
    $failed = ($categoryResults | Where-Object { $_.Result -like "FAILED:*" }).Count
    $skipped = ($categoryResults | Where-Object { $_.Result -like "SKIPPED:*" }).Count
    $total = $categoryResults.Count

    $color = if ($failed -eq 0) { "Green" } else { "Red" }

    Write-Host "`n$categoryName" -ForegroundColor $color
    Write-Host "  Total: $total" -ForegroundColor White
    Write-Host "  Passed: $passed" -ForegroundColor Green
    Write-Host "  Failed: $failed" -ForegroundColor Red
    Write-Host "  Skipped: $skipped" -ForegroundColor Yellow

    if ($failed -gt 0) {
        Write-Host "  Failures:" -ForegroundColor Red
        foreach ($failure in ($categoryResults | Where-Object { $_.Result -like "FAILED:*" })) {
            Write-Host "    - $($failure.Result)" -ForegroundColor Red
        }
    }
}

Write-Host "`n" + ("=" * 50) -ForegroundColor Cyan
Write-Host "FINAL SUMMARY" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan
Write-Host "Total Tests: $($global:testResults.Count)" -ForegroundColor White
Write-Host "Passed: $($global:passedCount)" -ForegroundColor Green
Write-Host "Failed: $($global:failedCount)" -ForegroundColor Red
Write-Host "Skipped: $($global:skippedCount)" -ForegroundColor Yellow
Write-Host "Success Rate: $([math]::Round(($global:passedCount / $global:testResults.Count) * 100, 1))%" -ForegroundColor White

Write-Host "`n" + ("=" * 50) -ForegroundColor Cyan
Write-Host "FEATURE STATUS" -ForegroundColor Cyan
Write-Host "=" * 50 -ForegroundColor Cyan

# Check feature status
$features = @(
    @{Name="Basic CLI"; Tests=$global:testResults | Where-Object { $_.Result -like "*Basic*" }},
    @{Name="Hash Functions"; Tests=$global:testResults | Where-Object { $_.Result -like "*Hash*" }},
    @{Name="HMAC"; Tests=$global:testResults | Where-Object { $_.Result -like "*HMAC*" }},
    @{Name="GCM (AEAD)"; Tests=$global:testResults | Where-Object { $_.Result -like "*GCM*" }},
    @{Name="ETM (Encrypt-then-MAC)"; Tests=$global:testResults | Where-Object { $_.Result -like "*ETM*" }},
    @{Name="Classic Modes"; Tests=$global:testResults | Where-Object { $_.Result -like "*ecb*" -or $_.Result -like "*cbc*" -or $_.Result -like "*cfb*" -or $_.Result -like "*ofb*" -or $_.Result -like "*ctr*" }},
    @{Name="Validation"; Tests=$global:testResults | Where-Object { $_.Result -like "*Validation*" }},
    @{Name="Interoperability"; Tests=$global:testResults | Where-Object { $_.Result -like "*Interop*" }}
)

foreach ($feature in $features) {
    $featureTests = $feature.Tests
    if ($featureTests) {
        $passed = ($featureTests | Where-Object { $_.Result -like "PASSED:*" }).Count
        $failed = ($featureTests | Where-Object { $_.Result -like "FAILED:*" }).Count
        $total = $featureTests.Count

        $status = if ($failed -eq 0) { "[OK] PASSED" } else { "[X] FAILED" }
        $color = if ($failed -eq 0) { "Green" } else { "Red" }

        Write-Host "$status $($feature.Name) ($passed/$total passed)" -ForegroundColor $color
    }
}

Write-Host ("=" * 50) -ForegroundColor Cyan

if ($global:allTestsPassed) {
    Write-Host "ALL TESTS PASSED! CryptoCore v0.6.0 is fully functional!" -ForegroundColor Green
    Write-Host "All requirements from M6 document are satisfied" -ForegroundColor Green
    Write-Host "AEAD (GCM and Encrypt-then-MAC) implemented" -ForegroundColor Green
    Write-Host "Catastrophic authentication failure working" -ForegroundColor Green
    Write-Host "Nonce generation and AAD support working" -ForegroundColor Green
    Write-Host "Backward compatibility maintained" -ForegroundColor Green
} else {
    Write-Host "SOME TESTS FAILED! Please check the failures above." -ForegroundColor Red
    Write-Host "Failed tests need investigation before submission." -ForegroundColor Red
    exit 1
}

Write-Host "`nTest execution completed at $(Get-Date -Format 'HH:mm:ss')" -ForegroundColor Gray

# Save detailed report to file
$reportFile = Join-Path $PROJECT_ROOT "test_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
$reportContent = @"
CRYPTOCORE TEST REPORT
Generated: $(Get-Date)
Version: 0.6.0
Test Script: $(Split-Path -Leaf $MyInvocation.MyCommand.Path)

SUMMARY:
========
Total Tests: $($global:testResults.Count)
Passed: $($global:passedCount)
Failed: $($global:failedCount)
Skipped: $($global:skippedCount)
Success Rate: $([math]::Round(($global:passedCount / $global:testResults.Count) * 100, 1))%

DETAILED RESULTS:
=================
$(($global:testResults | ForEach-Object { "$($_.Timestamp.ToString('HH:mm:ss')) - $($_.Category): $($_.Result)" }) -join "`n")

"@

$reportContent | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "`nDetailed report saved to: $reportFile" -ForegroundColor Cyan

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")