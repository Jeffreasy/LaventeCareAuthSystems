# Register User - LaventeCare Auth System
# Creates a new user account

$TENANT_ID = "c3888c7e-44cf-4827-9a7d-adaae2a1a095"
$API_URL = "https://laventecareauthsystems.onrender.com/api/v1"

Write-Host "`n=== LaventeCare User Registration ===" -ForegroundColor Cyan

# User credentials
$email = "jeffrey@smartcoolcare.nl"
$password = "Oprotten@12"
$fullName = "Jeffrey Lavente"

Write-Host "`nRegistering user..." -ForegroundColor Yellow
Write-Host "  Email: $email" -ForegroundColor Gray
Write-Host "  Tenant: $TENANT_ID" -ForegroundColor Gray

# Prepare request body
$body = @{
    email     = $email
    password  = $password
    full_name = $fullName
} | ConvertTo-Json

try {
    $response = Invoke-WebRequest -Method POST `
        -Uri "$API_URL/auth/register" `
        -Headers @{
        "X-Tenant-ID"  = $TENANT_ID
        "Content-Type" = "application/json"
    } `
        -Body $body `
        -UseBasicParsing

    Write-Host "`n✅ Registration successful!" -ForegroundColor Green
    Write-Host "Status: $($response.StatusCode)" -ForegroundColor Green
    
    # Parse response
    $userData = $response.Content | ConvertFrom-Json
    Write-Host "`nUser Details:" -ForegroundColor White
    Write-Host "  ID: $($userData.user.id)" -ForegroundColor Gray
    Write-Host "  Email: $($userData.user.email)" -ForegroundColor Gray
    Write-Host "  Email Verified: $($userData.user.is_email_verified)" -ForegroundColor Gray
    
    Write-Host "`n🎉 You can now login at your frontend!`n" -ForegroundColor Green
    
}
catch {
    $statusCode = $_.Exception.Response.StatusCode.value__
    
    if ($statusCode -eq 409) {
        Write-Host "`n⚠️  User already exists!" -ForegroundColor Yellow
        Write-Host "You can login with this email.`n" -ForegroundColor Yellow
    }
    else {
        Write-Host "`n❌ Registration failed" -ForegroundColor Red
        Write-Host "Status: $statusCode" -ForegroundColor Red
        
        try {
            $reader = [System.IO.StreamReader]::new($_.Exception.Response.GetResponseStream())
            $errorBody = $reader.ReadToEnd()
            Write-Host "Error: $errorBody`n" -ForegroundColor Red
        }
        catch {
            Write-Host "Error: $($_.Exception.Message)`n" -ForegroundColor Red
        }
    }
}
