# Inicia los servicios iniciales
docker-compose up -d mapfs-cloud mapfs-device mapfs-gateway sniffer-capture

# Espera 2 minutos (120 segundos) Windows
Start-Sleep -Seconds 120

# Linux
sleep 120

# Detiene los servicios iniciales
docker-compose stop mapfs-cloud mapfs-device mapfs-gateway sniffer-capture

# Inicia los servicios restantes con el perfil "delayed"
docker-compose --profile delayed up -d