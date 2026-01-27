# Fix CORS - Add localhost to allowed origins
# Run this ONCE to configure your tenant

$TENANT_ID = "c3888c7e-44cf-4827-9a7d-adaae2a1a095"
$API_URL = "https://laventecareauthsystems.onrender.com/api/v1"

Write-Host "`nAdding localhost to CORS whitelist..." -ForegroundColor Cyan

# First, you need to login as admin to get a JWT
# For now, we'll update via direct database or use a temp admin endpoint

# Option 1: Update CORS via API (requires admin JWT)
$corsOrigins = @(
    "http://localhost:4321",
    "http://localhost:3000",
    "http://127.0.0.1:4321",
    "https://dekoninklijkeloop.nl",
    "https://www.dekoninklijkeloop.nl"
)

$body = @{
    allowed_origins = $corsOrigins
} | ConvertTo-Json

Write-Host "CORS Origins to add:" -ForegroundColor Yellow
$corsOrigins | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }

Write-Host "`n⚠️  You need to update CORS via one of these methods:" -ForegroundColor Yellow
Write-Host "1. Direct database update (SQL)" -ForegroundColor White
Write-Host "2. Admin API call (need admin JWT)" -ForegroundColor White
Write-Host "3. Temporarily disable CORS validation" -ForegroundColor White

Write-Host "`n--- SQL Option (Run in Database) ---" -ForegroundColor Cyan
Write-Host @"
UPDATE tenants
SET allowed_origins = ARRAY[
    'http://localhost:4321',
    'http://localhost:3000', 
    'http://127.0.0.1:4321',
    'https://dekoninklijkeloop.nl',
    'https://www.dekoninklijkeloop.nl'
]
WHERE id = '$TENANT_ID';
"@ -ForegroundColor Green

Write-Host "`n--- OR Create Admin User First ---" -ForegroundColor Cyan
Write-Host "Then use: PUT $API_URL/admin/cors-origins" -ForegroundColor Green
