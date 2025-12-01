# Mock Zoho API Listener
Write-Host "Starting Mock Zoho API on port 19001..." -ForegroundColor Green

$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add("http://127.0.0.1:19001/")
try {
    $listener.Start()
    Write-Host "Mock Zoho listening on http://localhost:19001/" -ForegroundColor Green
}
catch {
    Write-Error "Failed to start listener on port 19001 (may already be in use): $_"
    exit 1
}

while ($true) {
    try {
        $ctx = $listener.GetContext()
        $req = $ctx.Request
        $body = ''
        if ($req.HasEntityBody) {
            $sr = New-Object System.IO.StreamReader($req.InputStream)
            $body = $sr.ReadToEnd()
            $sr.Close()
        }
        
        Write-Host "`n[$(Get-Date -Format 'HH:mm:ss')] ZOHO MOCK: $($req.HttpMethod) $($req.RawUrl)" -ForegroundColor Yellow
        Write-Host "Headers: $($req.Headers.AllKeys | ForEach-Object { "$_=$($req.Headers[$_])" } | Out-String)" -ForegroundColor Gray
        Write-Host "Body: $body" -ForegroundColor Gray
        
        $respObj = @{ status = "success"; id = (Get-Random); message = "Comment posted" } | ConvertTo-Json
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($respObj)
        $ctx.Response.ContentType = "application/json"
        $ctx.Response.ContentLength64 = $bytes.Length
        $ctx.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $ctx.Response.StatusCode = 200
        $ctx.Response.OutputStream.Close()
        
        Write-Host "Response: 200 OK" -ForegroundColor Green
    }
    catch {
        Write-Error "Error handling request: $_"
    }
}
