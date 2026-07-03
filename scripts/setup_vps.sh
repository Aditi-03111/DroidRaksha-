#!/bin/bash
set -e

# ==============================================================================
# DroidRaksha — VPS Setup Script
# Run this script on a fresh Ubuntu 22.04+ VPS to set up Docker and deploy.
# ==============================================================================

echo "🚀 Starting DroidRaksha VPS Provisioning..."

# 1. Update system and install dependencies
echo "📦 Updating system..."
sudo apt-get update -y
sudo apt-get upgrade -y
sudo apt-get install -y apt-transport-https ca-certificates curl software-properties-common git jq

# 2. Install Docker & Docker Compose
if ! command -v docker &> /dev/null; then
    echo "🐳 Installing Docker..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sudo sh get-docker.sh
    sudo usermod -aG docker $USER
    rm get-docker.sh
    echo "✅ Docker installed. (You may need to log out and log back in for group changes to apply)"
else
    echo "✅ Docker is already installed."
fi

# 3. Setup Project Directory
PROJECT_DIR="$HOME/DroidRaksha"
if [ ! -d "$PROJECT_DIR" ]; then
    echo "📁 Creating project directory..."
    mkdir -p $PROJECT_DIR
fi
cd $PROJECT_DIR

# 4. Create necessary local directories
mkdir -p uploads

# 5. Download docker-compose.yml
echo "📥 Downloading deployment configurations..."
# NOTE: Replace 'praju455' and 'main' with your fork/branch if necessary.
curl -fsSL https://raw.githubusercontent.com/praju455/DroidRaksha-/main/docker-compose.yml -o docker-compose.yml

# 6. Prompt for Environment Variables (if .env doesn't exist)
if [ ! -f ".env" ]; then
    echo "⚙️ Creating .env file..."
    read -p "Enter GEMINI_API_KEY: " GEMINI_API_KEY
    read -p "Enter GROQ_API_KEY: " GROQ_API_KEY
    read -p "Enter VIRUSTOTAL_API_KEY: " VIRUSTOTAL_API_KEY
    read -p "Enter ABUSEIPDB_API_KEY: " ABUSEIPDB_API_KEY

    cat <<EOF > .env
GEMINI_API_KEY=$GEMINI_API_KEY
GROQ_API_KEY=$GROQ_API_KEY
VIRUSTOTAL_API_KEY=$VIRUSTOTAL_API_KEY
ABUSEIPDB_API_KEY=$ABUSEIPDB_API_KEY
DATABASE_URL=sqlite+aiosqlite:///./droidraksha.db
UPLOAD_DIR=./uploads
EOF
    echo "✅ .env file created."
fi

# 7. Pull images and start the stack
echo "🚀 Starting Docker Compose stack..."
# Since images are built by GitHub Actions and pushed to GHCR, we should pull them.
# The docker-compose.yml by default builds locally. We need to override it to use the GHCR images.

# Create an override file for production
cat <<EOF > docker-compose.override.yml
version: "3.9"
services:
  backend:
    image: ghcr.io/praju455/droidraksha-:main
    build: null
  worker:
    image: ghcr.io/praju455/droidraksha-:main
    build: null
  frontend:
    # If deploying frontend to Vercel, we can scale this down to 0 or leave it out.
    # To disable frontend on VPS:
    profiles: ["donotstart"]
EOF

echo "📥 Pulling images..."
docker compose pull

echo "🚀 Spinning up containers..."
docker compose up -d

echo "======================================================================"
echo "✅ DroidRaksha Deployment Complete!"
echo "📡 Backend is running on: http://\$(curl -s ifconfig.me):8000"
echo "======================================================================"
