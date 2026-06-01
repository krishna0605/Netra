$ErrorActionPreference = "Stop"
Invoke-RestMethod -Method Post -Uri "http://localhost:8080/api/retention/execute" | ConvertTo-Json -Depth 8
