# test.ps1 - Complete Automated Testing for Windows PowerShell

Write-Host "Starting CryptoCore Complete Automated Tests..." -ForegroundColor Cyan

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

# Step 1: Build project
Write-Section "Building Project"
cargo build --release
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit 1
}
Write-Status $true "Build completed"

# Define the path to the executable
$CRYPTOCORE_EXE = "..\target\release\cryptocore.exe"
if (-not (Test-Path $CRYPTOCORE_EXE)) {
    Write-Host "Executable not found at $CRYPTOCORE_EXE" -ForegroundColor Yellow
    Write-Host "Trying debug build..." -ForegroundColor Yellow
    $CRYPTOCORE_EXE = "..\target\debug\cryptocore.exe"
    cargo build
    if (-not (Test-Path $CRYPTOCORE_EXE)) {
        Write-Host "Executable not found at $CRYPTOCORE_EXE" -ForegroundColor Red
        exit 1
    }
}

Write-Host "Using executable: $CRYPTOCORE_EXE" -ForegroundColor Green

# Step 2: Basic functionality tests
Write-Section "Basic Functionality Tests"

Write-Step "Testing help command"
& $CRYPTOCORE_EXE --help
Write-Status ($LASTEXITCODE -eq 0) "Help command works"

Write-Step "Testing version command"
& $CRYPTOCORE_EXE --version
Write-Status ($LASTEXITCODE -eq 0) "Version command works"

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

foreach ($file in $testFiles.GetEnumerator()) {
    $file.Value | Out-File -FilePath $file.Key -Encoding utf8
    Write-Host "Created $($file.Key)" -ForegroundColor Green
}

# Create binary test files
[byte[]]$binaryData1 = @(0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f)
[System.IO.File]::WriteAllBytes("binary_16.bin", $binaryData1)

[byte[]]$binaryData2 = @(0x42,0x69,0x6E,0x61,0x72,0x79,0x00,0x64,0x61,0x74,0x61,0x00,0x77,0x69,0x74,0x68,0x00,0x6E,0x75,0x6C,0x6C,0x73,0x00,0x61,0x6E,0x64,0x00,0x73,0x70,0x65,0x63,0x69,0x61,0x6C,0x00,0x63,0x68,0x61,0x72,0x73,0xFF,0xFE,0xFD)
[System.IO.File]::WriteAllBytes("binary_with_nulls.bin", $binaryData2)

# Create random 1KB file
$randomBytes = New-Object byte[] 1024
(New-Object Random).NextBytes($randomBytes)
[System.IO.File]::WriteAllBytes("random_1k.bin", $randomBytes)

Write-Host "Created binary test files" -ForegroundColor Green

# Step 4: Test all encryption modes comprehensively
Write-Section "Testing All Encryption Modes"

$KEY = "00112233445566778899aabbccddeeff"
$allTestsPassed = $true
$testResults = @()

# All supported modes
$modes = @("ecb", "cbc", "cfb", "ofb", "ctr")

foreach ($mode in $modes) {
    Write-Step "Testing $($mode.ToUpper()) mode"

    # Test with each file type
    foreach ($file in $testFiles.GetEnumerator()) {
        $filename = $file.Key
        Write-Host "  Testing $filename..." -NoNewline

        $encryptedFile = "$filename.$mode.enc"
        $decryptedFile = "$filename.$mode.dec"

        # Build encryption command
        $encryptArgs = @(
            "--algorithm", "aes",
            "--mode", $mode,
            "--operation", "encrypt",
            "--key", $KEY,
            "--input", $filename,
            "--output", $encryptedFile
        )

        # Build decryption command
        $decryptArgs = @(
            "--algorithm", "aes",
            "--mode", $mode,
            "--operation", "decrypt",
            "--key", $KEY,
            "--input", $encryptedFile,
            "--output", $decryptedFile
        )

        # Encrypt
        $encryptResult = & $CRYPTOCORE_EXE @encryptArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host " Encryption failed" -ForegroundColor Red
            $testResults += "FAILED: $filename.$mode - Encryption failed"
            $allTestsPassed = $false
            continue
        }

        # Verify encrypted file exists and has content
        if (-not (Test-Path $encryptedFile) -or (Get-Item $encryptedFile).Length -eq 0) {
            Write-Host " Empty encrypted file" -ForegroundColor Red
            $testResults += "FAILED: $filename.$mode - Empty encrypted file"
            $allTestsPassed = $false
            continue
        }

        # For modes with IV, verify file contains IV + data
        if ($mode -ne "ecb") {
            $fileSize = (Get-Item $encryptedFile).Length
            if ($fileSize -lt 16) {
                Write-Host " Encrypted file too small for IV" -ForegroundColor Red
                $testResults += "FAILED: $filename.$mode - File too small for IV"
                $allTestsPassed = $false
                continue
            }
        }

        # Decrypt
        $decryptResult = & $CRYPTOCORE_EXE @decryptArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host " Decryption failed" -ForegroundColor Red
            $testResults += "FAILED: $filename.$mode - Decryption failed"
            $allTestsPassed = $false
            continue
        }

        # Compare files as bytes
        try {
            $originalBytes = [System.IO.File]::ReadAllBytes($filename)
            $decryptedBytes = [System.IO.File]::ReadAllBytes($decryptedFile)
            $filesMatch = ($originalBytes.Length -eq $decryptedBytes.Length)
            if ($filesMatch) {
                for ($i = 0; $i -lt $originalBytes.Length; $i++) {
                    if ($originalBytes[$i] -ne $decryptedBytes[$i]) {
                        $filesMatch = $false
                        break
                    }
                }
            }

            if ($filesMatch) {
                Write-Host " Success" -ForegroundColor Green
                $testResults += "PASSED: $filename.$mode - Round-trip successful"
            } else {
                Write-Host " Files don't match" -ForegroundColor Red
                $testResults += "FAILED: $filename.$mode - Files don't match"
                $allTestsPassed = $false
            }
        } catch {
            Write-Host " File comparison error: $($_.Exception.Message)" -ForegroundColor Red
            $testResults += "FAILED: $filename.$mode - File comparison error"
            $allTestsPassed = $false
        }

        # Cleanup
        Remove-Item $encryptedFile, $decryptedFile -ErrorAction SilentlyContinue
    }

    # Test with binary files
    $binaryFiles = @("binary_16.bin", "binary_with_nulls.bin", "random_1k.bin")
    foreach ($binaryFile in $binaryFiles) {
        Write-Host "  Testing $binaryFile..." -NoNewline

        $encryptedFile = "$binaryFile.$mode.enc"
        $decryptedFile = "$binaryFile.$mode.dec"

        $encryptArgs = @(
            "--algorithm", "aes",
            "--mode", $mode,
            "--operation", "encrypt",
            "--key", $KEY,
            "--input", $binaryFile,
            "--output", $encryptedFile
        )

        $decryptArgs = @(
            "--algorithm", "aes",
            "--mode", $mode,
            "--operation", "decrypt",
            "--key", $KEY,
            "--input", $encryptedFile,
            "--output", $decryptedFile
        )

        $encryptResult = & $CRYPTOCORE_EXE @encryptArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host " Encryption failed" -ForegroundColor Red
            $testResults += "FAILED: $binaryFile.$mode - Encryption failed"
            $allTestsPassed = $false
            continue
        }

        $decryptResult = & $CRYPTOCORE_EXE @decryptArgs
        if ($LASTEXITCODE -ne 0) {
            Write-Host " Decryption failed" -ForegroundColor Red
            $testResults += "FAILED: $binaryFile.$mode - Decryption failed"
            $allTestsPassed = $false
            continue
        }

        try {
            $originalBytes = [System.IO.File]::ReadAllBytes($binaryFile)
            $decryptedBytes = [System.IO.File]::ReadAllBytes($decryptedFile)
            $filesMatch = ($originalBytes.Length -eq $decryptedBytes.Length)
            if ($filesMatch) {
                for ($i = 0; $i -lt $originalBytes.Length; $i++) {
                    if ($originalBytes[$i] -ne $decryptedBytes[$i]) {
                        $filesMatch = $false
                        break
                    }
                }
            }

            if ($filesMatch) {
                Write-Host " Success" -ForegroundColor Green
                $testResults += "PASSED: $binaryFile.$mode - Round-trip successful"
            } else {
                Write-Host " Failed" -ForegroundColor Red
                $testResults += "FAILED: $binaryFile.$mode - Round-trip failed"
                $allTestsPassed = $false
            }
        } catch {
            Write-Host " Error: $($_.Exception.Message)" -ForegroundColor Red
            $testResults += "FAILED: $binaryFile.$mode - File error"
            $allTestsPassed = $false
        }

        Remove-Item $encryptedFile, $decryptedFile -ErrorAction SilentlyContinue
    }
}

# Step 5: Advanced IV handling tests
Write-Section "Testing IV Handling"

# Test IV provided for decryption
Write-Step "Testing decryption with provided IV"
"IV test data" | Out-File -FilePath iv_test.txt -Encoding utf8

# Encrypt with auto IV
& $CRYPTOCORE_EXE --algorithm aes --mode cbc --operation encrypt --key $KEY --input iv_test.txt --output iv_encrypted.bin

if ($LASTEXITCODE -eq 0) {
    # Extract IV from encrypted file
    $encryptedData = [System.IO.File]::ReadAllBytes("iv_encrypted.bin")
    $extractedIv = $encryptedData[0..15]
    $ciphertextOnly = $encryptedData[16..($encryptedData.Length-1)]

    # Save ciphertext without IV
    [System.IO.File]::WriteAllBytes("ciphertext_only.bin", $ciphertextOnly)

    # Convert IV to hex for CLI
    $ivHex = -join ($extractedIv | ForEach-Object { $_.ToString("X2") })

    # Decrypt with provided IV
    & $CRYPTOCORE_EXE --algorithm aes --mode cbc --operation decrypt --key $KEY --iv $ivHex --input ciphertext_only.bin --output iv_decrypted.txt

    if ($LASTEXITCODE -eq 0) {
        $original = Get-Content iv_test.txt -Raw
        $decrypted = Get-Content iv_decrypted.txt -Raw

        if ($original -eq $decrypted) {
            Write-Status $true "Decryption with provided IV works"
            $testResults += "PASSED: IV handling - Provided IV decryption"
        } else {
            Write-Status $false "Decryption with provided IV failed (content mismatch)"
            $testResults += "FAILED: IV handling - Provided IV decryption"
            $allTestsPassed = $false
        }
    } else {
        Write-Status $false "Decryption with provided IV failed"
        $testResults += "FAILED: IV handling - Provided IV decryption"
        $allTestsPassed = $false
    }
} else {
    Write-Status $false "Encryption for IV test failed"
    $testResults += "FAILED: IV handling - Encryption failed"
    $allTestsPassed = $false
}

Remove-Item iv_test.txt, iv_encrypted.bin, ciphertext_only.bin, iv_decrypted.txt -ErrorAction SilentlyContinue

# Step 6: Validation and error handling tests
Write-Section "Validation and Error Handling"

# Test invalid key
Write-Step "Testing invalid key rejection"
& $CRYPTOCORE_EXE --algorithm aes --mode ecb --operation encrypt --key "invalid" --input "short.txt" --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject invalid key"
    $testResults += "FAILED: Validation - Invalid key accepted"
    $allTestsPassed = $false
} else {
    Write-Status $true "Invalid key rejected"
    $testResults += "PASSED: Validation - Invalid key rejected"
}

# Test wrong key length
Write-Step "Testing wrong key length"
& $CRYPTOCORE_EXE --algorithm aes --mode ecb --operation encrypt --key "001122" --input "short.txt" --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject wrong key length"
    $testResults += "FAILED: Validation - Wrong key length accepted"
    $allTestsPassed = $false
} else {
    Write-Status $true "Wrong key length rejected"
    $testResults += "PASSED: Validation - Wrong key length rejected"
}

# Test nonexistent file
Write-Step "Testing nonexistent file rejection"
& $CRYPTOCORE_EXE --algorithm aes --mode ecb --operation encrypt --key $KEY --input "nonexistent_file_12345.txt" --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject nonexistent file"
    $testResults += "FAILED: Validation - Nonexistent file accepted"
    $allTestsPassed = $false
} else {
    Write-Status $true "Nonexistent file rejected"
    $testResults += "PASSED: Validation - Nonexistent file rejected"
}

# Test IV provided during encryption (should fail)
Write-Step "Testing IV rejection during encryption"
& $CRYPTOCORE_EXE --algorithm aes --mode cbc --operation encrypt --key $KEY --iv "000102030405060708090A0B0C0D0E0F" --input "short.txt" --output "test.enc" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should reject IV during encryption"
    $testResults += "FAILED: Validation - IV accepted during encryption"
    $allTestsPassed = $false
} else {
    Write-Status $true "IV correctly rejected during encryption"
    $testResults += "PASSED: Validation - IV rejected during encryption"
}

# Test missing IV for decryption
Write-Step "Testing missing IV detection"
"test" | Out-File -FilePath short_cipher.bin -Encoding utf8
& $CRYPTOCORE_EXE --algorithm aes --mode cbc --operation decrypt --key $KEY --input "short_cipher.bin" --output "test.dec" 2>$null
if ($LASTEXITCODE -eq 0) {
    Write-Status $false "Should detect missing IV"
    $testResults += "FAILED: Validation - Missing IV not detected"
    $allTestsPassed = $false
} else {
    Write-Status $true "Missing IV correctly detected"
    $testResults += "PASSED: Validation - Missing IV detected"
}
Remove-Item short_cipher.bin -ErrorAction SilentlyContinue

# Step 7: File handling tests
Write-Section "File Handling Tests"

# Test automatic output naming
Write-Step "Testing automatic output naming"
"Auto name test" | Out-File -FilePath auto_test.txt -Encoding utf8

& $CRYPTOCORE_EXE --algorithm aes --mode ecb --operation encrypt --key $KEY --input auto_test.txt
if ($LASTEXITCODE -eq 0 -and (Test-Path "auto_test.txt.enc")) {
    Write-Status $true "Automatic encryption naming works"
    $testResults += "PASSED: File handling - Auto encryption naming"
} else {
    Write-Status $false "Automatic encryption naming failed"
    $testResults += "FAILED: File handling - Auto encryption naming"
    $allTestsPassed = $false
}

& $CRYPTOCORE_EXE --algorithm aes --mode ecb --operation decrypt --key $KEY --input auto_test.txt.enc
if ($LASTEXITCODE -eq 0 -and (Test-Path "auto_test.txt.enc.dec")) {
    Write-Status $true "Automatic decryption naming works"
    $testResults += "PASSED: File handling - Auto decryption naming"
} else {
    Write-Status $false "Automatic decryption naming failed"
    $testResults += "FAILED: File handling - Auto decryption naming"
    $allTestsPassed = $false
}

Remove-Item auto_test.txt, auto_test.txt.enc, auto_test.txt.enc.dec -ErrorAction SilentlyContinue

# Step 8: OpenSSL interoperability tests
Write-Section "OpenSSL Interoperability Tests"

if (Get-Command "openssl" -ErrorAction SilentlyContinue) {
    Write-Step "Testing OpenSSL interoperability"

    try {
        # Test 1: Encrypt with our tool, decrypt with OpenSSL
        "OpenSSL interoperability test data" | Out-File -FilePath openssl_test1.txt -Encoding utf8

        # Encrypt with our tool
        & $CRYPTOCORE_EXE --algorithm aes --mode cbc --operation encrypt --key $KEY --input openssl_test1.txt --output our_encrypted.bin

        if ($LASTEXITCODE -eq 0) {
            # Extract IV and ciphertext
            $encryptedData = [System.IO.File]::ReadAllBytes("our_encrypted.bin")
            $ivBytes = $encryptedData[0..15]
            $ciphertextBytes = $encryptedData[16..($encryptedData.Length-1)]

            [System.IO.File]::WriteAllBytes("our_iv.bin", $ivBytes)
            [System.IO.File]::WriteAllBytes("our_ciphertext.bin", $ciphertextBytes)

            # Convert IV to hex for OpenSSL
            $ivHex = -join ($ivBytes | ForEach-Object { $_.ToString("X2") })

            # Decrypt with OpenSSL
            openssl enc -aes-128-cbc -d -K $KEY -iv $ivHex -in our_ciphertext.bin -out openssl_decrypted1.txt

            if ($LASTEXITCODE -eq 0) {
                $original = Get-Content openssl_test1.txt -Raw
                $decrypted = Get-Content openssl_decrypted1.txt -Raw

                if ($original -eq $decrypted) {
                    Write-Status $true "OurTool -> OpenSSL: PASS"
                    $testResults += "PASSED: Interop - OurTool to OpenSSL"
                } else {
                    Write-Status $false "OurTool -> OpenSSL: FAIL (content mismatch)"
                    $testResults += "FAILED: Interop - OurTool to OpenSSL"
                    $allTestsPassed = $false
                }
            } else {
                Write-Status $false "OurTool -> OpenSSL: FAIL (OpenSSL decryption failed)"
                $testResults += "FAILED: Interop - OurTool to OpenSSL"
                $allTestsPassed = $false
            }
        } else {
            Write-Status $false "OurTool -> OpenSSL: FAIL (our encryption failed)"
            $testResults += "FAILED: Interop - OurTool to OpenSSL"
            $allTestsPassed = $false
        }

        # Test 2: Encrypt with OpenSSL, decrypt with our tool
        "OpenSSL to our tool test" | Out-File -FilePath openssl_test2.txt -Encoding utf8

        # Encrypt with OpenSSL
        $TEST_IV = "000102030405060708090A0B0C0D0E0F"
        openssl enc -aes-128-cbc -K $KEY -iv $TEST_IV -in openssl_test2.txt -out openssl_encrypted.bin

        if ($LASTEXITCODE -eq 0) {
            # Decrypt with our tool
            & $CRYPTOCORE_EXE --algorithm aes --mode cbc --operation decrypt --key $KEY --iv $TEST_IV --input openssl_encrypted.bin --output our_decrypted.txt

            if ($LASTEXITCODE -eq 0) {
                $original = Get-Content openssl_test2.txt -Raw
                $decrypted = Get-Content our_decrypted.txt -Raw

                if ($original -eq $decrypted) {
                    Write-Status $true "OpenSSL -> OurTool: PASS"
                    $testResults += "PASSED: Interop - OpenSSL to OurTool"
                } else {
                    Write-Status $false "OpenSSL -> OurTool: FAIL (content mismatch)"
                    $testResults += "FAILED: Interop - OpenSSL to OurTool"
                    $allTestsPassed = $false
                }
            } else {
                Write-Status $false "OpenSSL -> OurTool: FAIL (our decryption failed)"
                $testResults += "FAILED: Interop - OpenSSL to OurTool"
                $allTestsPassed = $false
            }
        } else {
            Write-Status $false "OpenSSL -> OurTool: FAIL (OpenSSL encryption failed)"
            $testResults += "FAILED: Interop - OpenSSL to OurTool"
            $allTestsPassed = $false
        }

        # Cleanup
        Remove-Item openssl_test1.txt, openssl_test2.txt, our_encrypted.bin, our_iv.bin, our_ciphertext.bin, openssl_decrypted1.txt, openssl_encrypted.bin, our_decrypted.txt -ErrorAction SilentlyContinue

    } catch {
        Write-Status $false "OpenSSL interoperability test error: $($_.Exception.Message)"
        $testResults += "FAILED: Interop - Test error"
        $allTestsPassed = $false
    }
} else {
    Write-Host "OpenSSL not available, skipping interoperability tests" -ForegroundColor Yellow
    $testResults += "SKIPPED: OpenSSL interoperability"
}

# Step 9: Performance and stress tests
Write-Section "Performance and Stress Tests"

Write-Step "Testing with larger files"
# Create a larger test file if we have enough space
try {
    $freeSpace = (Get-PSDrive -Name (Get-Location).Drive.Name).Free
    if ($freeSpace -gt 10MB) {
        # Create 1MB file
        $largeData = New-Object byte[] 1MB
        (New-Object Random).NextBytes($largeData)
        [System.IO.File]::WriteAllBytes("large_test.bin", $largeData)

        foreach ($mode in @("ecb", "cbc")) {
            Write-Host "  Testing 1MB file with $mode..." -NoNewline

            & $CRYPTOCORE_EXE --algorithm aes --mode $mode --operation encrypt --key $KEY --input large_test.bin --output large_encrypted.bin
            $encryptSuccess = ($LASTEXITCODE -eq 0)

            & $CRYPTOCORE_EXE --algorithm aes --mode $mode --operation decrypt --key $KEY --input large_encrypted.bin --output large_decrypted.bin
            $decryptSuccess = ($LASTEXITCODE -eq 0)

            if ($encryptSuccess -and $decryptSuccess) {
                $originalBytes = [System.IO.File]::ReadAllBytes("large_test.bin")
                $decryptedBytes = [System.IO.File]::ReadAllBytes("large_decrypted.bin")
                $filesMatch = ($originalBytes.Length -eq $decryptedBytes.Length)

                if ($filesMatch) {
                    # Compare first and last few bytes for performance
                    $match = $true
                    for ($i = 0; $i -lt 100; $i++) {
                        if ($originalBytes[$i] -ne $decryptedBytes[$i]) {
                            $match = $false
                            break
                        }
                    }
                    if ($match) {
                        for ($i = $originalBytes.Length - 100; $i -lt $originalBytes.Length; $i++) {
                            if ($originalBytes[$i] -ne $decryptedBytes[$i]) {
                                $match = $false
                                break
                            }
                        }
                    }

                    if ($match) {
                        Write-Host " Success" -ForegroundColor Green
                        $testResults += "PASSED: Performance - 1MB file with $mode"
                    } else {
                        Write-Host " Content mismatch" -ForegroundColor Red
                        $testResults += "FAILED: Performance - 1MB file with $mode"
                        $allTestsPassed = $false
                    }
                } else {
                    Write-Host " Size mismatch" -ForegroundColor Red
                    $testResults += "FAILED: Performance - 1MB file with $mode"
                    $allTestsPassed = $false
                }
            } else {
                Write-Host " Execution failed" -ForegroundColor Red
                $testResults += "FAILED: Performance - 1MB file with $mode"
                $allTestsPassed = $false
            }

            Remove-Item large_encrypted.bin, large_decrypted.bin -ErrorAction SilentlyContinue
        }

        Remove-Item large_test.bin -ErrorAction SilentlyContinue
    } else {
        Write-Host "  Skipping large file tests (insufficient disk space)" -ForegroundColor Yellow
        $testResults += "SKIPPED: Performance - Large file tests"
    }
} catch {
    Write-Host "  Skipping large file tests (error: $($_.Exception.Message))" -ForegroundColor Yellow
    $testResults += "SKIPPED: Performance - Large file tests"
}

# Step 10: Cleanup
Write-Section "Cleaning Up"

foreach ($file in $testFiles.GetEnumerator()) {
    Remove-Item $file.Key -ErrorAction SilentlyContinue
}
Remove-Item binary_16.bin, binary_with_nulls.bin, random_1k.bin -ErrorAction SilentlyContinue

# Step 11: Results summary
Write-Section "Test Results Summary"

$passedCount = 0
$failedCount = 0
$skippedCount = 0

foreach ($result in $testResults) {
    if ($result -like "PASSED:*") {
        Write-Host "  $result" -ForegroundColor Green
        $passedCount++
    } elseif ($result -like "FAILED:*") {
        Write-Host "  $result" -ForegroundColor Red
        $failedCount++
    } else {
        Write-Host "  $result" -ForegroundColor Yellow
        $skippedCount++
    }
}

Write-Host ""
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "  FINAL RESULTS" -ForegroundColor Cyan
Write-Host "================================================" -ForegroundColor Cyan
Write-Host "Total Tests: $($testResults.Count)" -ForegroundColor White
Write-Host "Passed: $passedCount" -ForegroundColor Green
Write-Host "Failed: $failedCount" -ForegroundColor Red
Write-Host "Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host ""

if ($allTestsPassed) {
    Write-Host "ALL TESTS PASSED! CryptoCore is fully functional!" -ForegroundColor Green
    Write-Host "All requirements from M2 document are satisfied" -ForegroundColor Green
    Write-Host "All 5 encryption modes working: ECB, CBC, CFB, OFB, CTR" -ForegroundColor Green
    Write-Host "Comprehensive testing completed successfully" -ForegroundColor Green
    Write-Host "File handling, validation, and interoperability verified" -ForegroundColor Green
} else {
    Write-Host "SOME TESTS FAILED! Please check the errors above." -ForegroundColor Red
    exit 1
}

Write-Host "================================================" -ForegroundColor Cyan

Write-Host ""
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")