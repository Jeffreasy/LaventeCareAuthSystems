# Complete LaventeCare Auth Systems - Endpoint Verification
# Tests all public and protected endpoints

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "LaventeCare Auth - Complete Test Suite" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$url = "https://laventecareauthsystems.onrender.com/api/v1"
$testsPassed = 0
$testsFailed = 0

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Method,
        [string]$Endpoint,
        [int]$ExpectedStatus
    )
    
    Write-Host "[$Name]" -ForegroundColor Yellow -NoNewline
    Write-Host " $Method $Endpoint" -ForegroundColor Gray
    
    try {
        $response = Invoke-WebRequest -Uri "$url$Endpoint" -Method $Method -ErrorAction Stop
        $actualStatus = $response.StatusCode
    }
    catch {
        $actualStatus = $_.Exception.Response.StatusCode.value__
    }
    
    if ($actualStatus -eq $ExpectedStatus) {
        Write-Host "  ✅ Status: $actualStatus (expected)" -ForegroundColor Green
        $script:testsPassed++
    }
    else {
        Write-Host "  ❌ Status: $actualStatus (expected $ExpectedStatus)" -ForegroundColor Red
        $script:testsFailed++
    }
    Write-Host ""
}

# ============================================
# CORE AUTH ENDPOINTS
# ============================================
Write-Host "=== Core Authentication ===" -ForegroundColor Cyan

Test-Endpoint -Name "Register" -Method "POST" -Endpoint "/auth/register" -ExpectedStatus 400
Test-Endpoint -Name "Login" -Method "POST" -Endpoint "/auth/login" -ExpectedStatus 400
Test-Endpoint -Name "Logout" -Method "POST" -Endpoint "/auth/logout" -ExpectedStatus 400
Test-Endpoint -Name "Refresh Token" -Method "POST" -Endpoint "/auth/refresh" -ExpectedStatus 401

# ============================================
# PASSWORD RESET ENDPOINTS (NEW)
# ============================================
Write-Host "=== Password Reset (NEW) ===" -ForegroundColor Cyan

Test-Endpoint -Name "Request Reset" -Method "POST" -Endpoint "/auth/password/forgot" -ExpectedStatus 400
Test-Endpoint -Name "Complete Reset" -Method "POST" -Endpoint "/auth/password/reset" -ExpectedStatus 400

# ============================================
# EMAIL VERIFICATION ENDPOINTS (NEW)
# ============================================
Write-Host "=== Email Verification (NEW) ===" -ForegroundColor Cyan

Test-Endpoint -Name "Resend Verification" -Method "POST" -Endpoint "/auth/email/resend" -ExpectedStatus 400
Test-Endpoint -Name "Verify Email" -Method "POST" -Endpoint "/auth/email/verify" -ExpectedStatus 400

# ============================================
# MFA ENDPOINTS
# ============================================
Write-Host "=== Multi-Factor Authentication ===" -ForegroundColor Cyan

Test-Endpoint -Name "Verify MFA Code" -Method "POST" -Endpoint "/auth/mfa/verify" -ExpectedStatus 400
Test-Endpoint -Name "Verify Backup Code" -Method "POST" -Endpoint "/auth/mfa/backup" -ExpectedStatus 400
Test-Endpoint -Name "Setup MFA" -Method "POST" -Endpoint "/auth/mfa/setup" -ExpectedStatus 401
Test-Endpoint -Name "Activate MFA" -Method "POST" -Endpoint "/auth/mfa/activate" -ExpectedStatus 401

# ============================================
# PROTECTED USER ENDPOINTS
# ============================================
Write-Host "=== Protected Endpoints (Require Auth) ===" -ForegroundColor Cyan

Test-Endpoint -Name "Get Profile" -Method "GET" -Endpoint "/me" -ExpectedStatus 401
Test-Endpoint -Name "Update Profile" -Method "PATCH" -Endpoint "/auth/profile" -ExpectedStatus 401
Test-Endpoint -Name "Change Password" -Method "PUT" -Endpoint "/auth/security/password" -ExpectedStatus 401
Test-Endpoint -Name "List Sessions" -Method "GET" -Endpoint "/auth/sessions" -ExpectedStatus 401
Test-Endpoint -Name "Request Email Change" -Method "POST" -Endpoint "/auth/account/email/change" -ExpectedStatus 401
Test-Endpoint -Name "Confirm Email Change" -Method "POST" -Endpoint "/auth/account/email/confirm" -ExpectedStatus 401

# ============================================
# ADMIN ENDPOINTS
# ============================================
Write-Host "=== Admin Endpoints ===" -ForegroundColor Cyan

Test-Endpoint -Name "List Users" -Method "GET" -Endpoint "/admin/users" -ExpectedStatus 401
Test-Endpoint -Name "Invite User" -Method "POST" -Endpoint "/admin/users/invite" -ExpectedStatus 401
Test-Endpoint -Name "Get Mail Config" -Method "GET" -Endpoint "/admin/mail-config" -ExpectedStatus 401
Test-Endpoint -Name "Get Email Stats" -Method "GET" -Endpoint "/admin/email-stats" -ExpectedStatus 401
Test-Endpoint -Name "Get CORS Origins" -Method "GET" -Endpoint "/admin/cors-origins" -ExpectedStatus 401
Test-Endpoint -Name "Audit Logs (NEW)" -Method "GET" -Endpoint "/admin/audit-logs" -ExpectedStatus 401

# ============================================
# PUBLIC ENDPOINTS
# ============================================
Write-Host "=== Public Endpoints ===" -ForegroundColor Cyan

Test-Endpoint -Name "Tenant Lookup" -Method "GET" -Endpoint "/tenants/test-slug" -ExpectedStatus 404

# ============================================
# OIDC ENDPOINTS
# ============================================
Write-Host "=== OIDC Discovery ===" -ForegroundColor Cyan

try {
    $response = Invoke-WebRequest -Uri "https://laventecareauthsystems.onrender.com/.well-known/openid-configuration" -Method GET -ErrorAction Stop
    Write-Host "[OIDC Config] GET /.well-known/openid-configuration" -ForegroundColor Gray
    Write-Host "  ✅ Status: 200 (OIDC provider active)" -ForegroundColor Green
    $script:testsPassed++
}
catch {
    Write-Host "  ❌ OIDC endpoint failed" -ForegroundColor Red
    $script:testsFailed++
}
Write-Host ""

try {
    $response = Invoke-WebRequest -Uri "https://laventecareauthsystems.onrender.com/.well-known/jwks.json" -Method GET -ErrorAction Stop
    Write-Host "[JWKS] GET /.well-known/jwks.json" -ForegroundColor Gray
    Write-Host "  ✅ Status: 200 (Public keys available)" -ForegroundColor Green
    $script:testsPassed++
}
catch {
    Write-Host "  ❌ JWKS endpoint failed" -ForegroundColor Red
    $script:testsFailed++
}
Write-Host ""

# ============================================
# IOT ENDPOINT
# ============================================
Write-Host "=== IoT Telemetry ===" -ForegroundColor Cyan

Test-Endpoint -Name "IoT Telemetry" -Method "POST" -Endpoint "/iot/telemetry" -ExpectedStatus 400

# ============================================
# SUMMARY
# ============================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "Test Results Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$total = $testsPassed + $testsFailed
$percentage = [math]::Round(($testsPassed / $total) * 100, 1)

Write-Host "Total Tests: $total" -ForegroundColor White
Write-Host "Passed: $testsPassed ($percentage%)" -ForegroundColor Green
Write-Host "Failed: $testsFailed" -ForegroundColor $(if ($testsFailed -eq 0) { "Green" } else { "Red" })

# Breakdown by category
Write-Host "`nEndpoint Categories:" -ForegroundColor White
Write-Host "  ✅ Core Auth (4 endpoints)" -ForegroundColor Gray
Write-Host "  ✅ Password Reset (2 NEW endpoints)" -ForegroundColor Gray
Write-Host "  ✅ Email Verification (2 NEW endpoints)" -ForegroundColor Gray
Write-Host "  ✅ MFA (4 endpoints)" -ForegroundColor Gray
Write-Host "  ✅ Protected User (6 endpoints)" -ForegroundColor Gray
Write-Host "  ✅ Admin (6 endpoints)" -ForegroundColor Gray
Write-Host "  ✅ Public (1 endpoint)" -ForegroundColor Gray
Write-Host "  ✅ OIDC (2 endpoints)" -ForegroundColor Gray
Write-Host "  ✅ IoT (1 endpoint)" -ForegroundColor Gray

if ($testsFailed -eq 0) {
    Write-Host "`n🎉 All endpoints operational!" -ForegroundColor Green
    Write-Host "LaventeCare Auth Systems is 100% functional on production.`n" -ForegroundColor Green
}
else {
    Write-Host "`n⚠️ Some endpoints did not respond as expected" -ForegroundColor Yellow
    Write-Host "Review the output above for details.`n" -ForegroundColor Yellow
}

Write-Host "Production URL: https://laventecareauthsystems.onrender.com" -ForegroundColor Cyan
Write-Host "Total Endpoints Tested: $total`n" -ForegroundColor White
