# LaventeCare Auth Systems - API Test Script
# Tests complete authentication flow on Render deployment

$baseUrl = "https://laventecareauthsystems.onrender.com"

Write-Host "🧪 LaventeCare Auth API - Flow Test" -ForegroundColor Cyan
Write-Host "Base URL: $baseUrl" -ForegroundColor White
Write-Host ""

# Step 1: Get CSRF Token
Write-Host "Step 1: Getting CSRF Token..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "$baseUrl/health" -Method GET -SessionVariable session -UseBasicParsing
    $csrfCookie = $session.Cookies.GetCookies($baseUrl) | Where-Object { $_.Name -eq "csrf_token" }
    
    if ($csrfCookie) {
        $csrfToken = $csrfCookie.Value
        Write-Host "✅ CSRF Token: $csrfToken" -ForegroundColor Green
    }
    else {
        Write-Host "⚠️  No CSRF token found (may not be required)" -ForegroundColor Yellow
        $csrfToken = ""
    }
}
catch {
    Write-Host "❌ Failed to get CSRF token: $_" -ForegroundColor Red
    $csrfToken = ""
}
Write-Host ""

# Step 2: Register New User
Write-Host "Step 2: Registering new user..." -ForegroundColor Yellow
$registerBody = @{
    email     = "testuser$(Get-Random -Minimum 1000 -Maximum 9999)@laventecare.nl"
    password  = "SecureTest123!"
    full_name = "Test User"
} | ConvertTo-Json

$headers = @{
    "Content-Type" = "application/json"
}

if ($csrfToken) {
    $headers["X-CSRF-Token"] = $csrfToken
}

try {
    $registerResponse = Invoke-WebRequest -Uri "$baseUrl/api/v1/auth/register" `
        -Method POST `
        -Body $registerBody `
        -Headers $headers `
        -WebSession $session `
        -UseBasicParsing
    
    $registerData = $registerResponse.Content | ConvertFrom-Json
    Write-Host "✅ Registration successful!" -ForegroundColor Green
    Write-Host "   User ID: $($registerData.user_id)" -ForegroundColor White
    Write-Host "   Email: $($registerData.email)" -ForegroundColor White
    
    # Save credentials for login
    $testEmail = ($registerBody | ConvertFrom-Json).email
    $testPassword = ($registerBody | ConvertFrom-Json).password
}
catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    $errorBody = $_.ErrorDetails.Message
    
    if ($statusCode -eq 403) {
        Write-Host "❌ CSRF Protection Active - API clients not supported without token flow" -ForegroundColor Red
        Write-Host "   This is expected for a production API with CSRF middleware" -ForegroundColor Yellow
        Write-Host "   Use a browser-based client or disable CSRF for public endpoints" -ForegroundColor Yellow
    }
    elseif ($statusCode -eq 400) {
        Write-Host "⚠️  Registration failed: $errorBody" -ForegroundColor Yellow
        Write-Host "   Public registration may be disabled (ALLOW_PUBLIC_REGISTRATION=false)" -ForegroundColor Yellow
    }
    else {
        Write-Host "❌ Registration failed: $statusCode - $errorBody" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "💡 Possible Solutions:" -ForegroundColor Cyan
    Write-Host "   1. Use a web client that supports cookies (browser, Postman)" -ForegroundColor White
    Write-Host "   2. Disable CSRF for public auth endpoints (register/login)" -ForegroundColor White
    Write-Host "   3. Enable ALLOW_PUBLIC_REGISTRATION in Render environment" -ForegroundColor White
    exit
}
Write-Host ""

# Step 3: Login
Write-Host "Step 3: Logging in..." -ForegroundColor Yellow
$loginBody = @{
    email    = $testEmail
    password = $testPassword
} | ConvertTo-Json

try {
    $loginResponse = Invoke-WebRequest -Uri "$baseUrl/api/v1/auth/login" `
        -Method POST `
        -Body $loginBody `
        -Headers $headers `
        -WebSession $session `
        -UseBasicParsing
    
    $loginData = $loginResponse.Content | ConvertFrom-Json
    Write-Host "✅ Login successful!" -ForegroundColor Green
    Write-Host "   Access Token: $($loginData.access_token.Substring(0, 20))..." -ForegroundColor White
    Write-Host "   Refresh Token: $($loginData.refresh_token.Substring(0, 20))..." -ForegroundColor White
    
    $accessToken = $loginData.access_token
    $refreshToken = $loginData.refresh_token
}
catch {
    Write-Host "❌ Login failed: $($_.ErrorDetails.Message)" -ForegroundColor Red
    exit
}
Write-Host ""

# Step 4: Access Protected Endpoint (/me)
Write-Host "Step 4: Accessing protected endpoint (/me)..." -ForegroundColor Yellow
$authHeaders = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

try {
    $meResponse = Invoke-WebRequest -Uri "$baseUrl/api/v1/me" `
        -Method GET `
        -Headers $authHeaders `
        -UseBasicParsing
    
    $meData = $meResponse.Content | ConvertFrom-Json
    Write-Host "✅ Profile retrieved!" -ForegroundColor Green
    Write-Host "   User ID: $($meData.id)" -ForegroundColor White
    Write-Host "   Email: $($meData.email)" -ForegroundColor White
    Write-Host "   Name: $($meData.full_name)" -ForegroundColor White
}
catch {
    Write-Host "❌ Failed to access /me: $($_.ErrorDetails.Message)" -ForegroundColor Red
}
Write-Host ""

# Step 5: Refresh Token
Write-Host "Step 5: Testing token refresh..." -ForegroundColor Yellow
$refreshBody = @{
    refresh_token = $refreshToken
} | ConvertTo-Json

try {
    $refreshResponse = Invoke-WebRequest -Uri "$baseUrl/api/v1/auth/refresh" `
        -Method POST `
        -Body $refreshBody `
        -Headers $headers `
        -WebSession $session `
        -UseBasicParsing
    
    $refreshData = $refreshResponse.Content | ConvertFrom-Json
    Write-Host "✅ Token refreshed!" -ForegroundColor Green
    Write-Host "   New Access Token: $($refreshData.access_token.Substring(0, 20))..." -ForegroundColor White
}
catch {
    Write-Host "❌ Token refresh failed: $($_.ErrorDetails.Message)" -ForegroundColor Red
}
Write-Host ""

Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
Write-Host "🎉 Auth Flow Test Complete!" -ForegroundColor Green
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Cyan
