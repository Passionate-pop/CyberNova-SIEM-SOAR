[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$env:DOCKER_HOST = "unix:///var/run/docker.sock"
$env:COMPOSE_DOCKER_CLI_BUILD = "1"
cd C:\Users\HP\CYBERNOVA

Write-Host "Building app..."
docker-compose build app 2>&1 | Select-Object -Last 5

Write-Host "Building workers..."
docker-compose build normalizer-worker detection-worker enrichment-worker correlation-worker soar-worker 2>&1 | Select-Object -Last 5

Write-Host "Restarting app and workers..."
docker-compose up -d --no-deps app normalizer-worker detection-worker enrichment-worker correlation-worker soar-worker 2>&1

Write-Host "Done."
