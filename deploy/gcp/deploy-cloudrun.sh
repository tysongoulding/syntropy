#!/usr/bin/env bash
# ==============================================================================
# Deploy Syntropy Gateway to Google Cloud Run (Serverless gRPC with HTTP/2)
# ==============================================================================
set -euo pipefail

PROJECT_ID="${1:-$(gcloud config get-value project)}"
REGION="${2:-us-central1}"
SERVICE_NAME="syntropy-gateway"
IMAGE_NAME="gcr.io/${PROJECT_ID}/${SERVICE_NAME}:latest"

echo "=========================================================="
echo "🚀 Deploying Syntropy Gateway to Google Cloud Run"
echo "   Project ID : ${PROJECT_ID}"
echo "   Region     : ${REGION}"
echo "   Image      : ${IMAGE_NAME}"
echo "=========================================================="

# 1. Build container image using Cloud Build
echo "📦 Building container image..."
gcloud builds submit --project="${PROJECT_ID}" \
    --config=deploy/docker/Dockerfile.cloud \
    --tag="${IMAGE_NAME}" .

# 2. Deploy to Cloud Run with native HTTP/2 for gRPC streaming
echo "☁️ Deploying to Cloud Run with end-to-end HTTP/2 gRPC support..."
gcloud run deploy "${SERVICE_NAME}" \
    --project="${PROJECT_ID}" \
    --region="${REGION}" \
    --image="${IMAGE_NAME}" \
    --platform=managed \
    --use-http2 \
    --port=50051 \
    --allow-unauthenticated \
    --cpu=1 \
    --memory=1Gi \
    --min-instances=1 \
    --timeout=3600 \
    --set-env-vars="RUST_LOG=info"

# 3. Retrieve Cloud Run HTTPS/gRPC endpoint
ENDPOINT=$(gcloud run services describe "${SERVICE_NAME}" --project="${PROJECT_ID}" --region="${REGION}" --format='value(status.url)')

echo "=========================================================="
echo "✅ Syntropy Gateway Deployed on Cloud Run Successfully!"
echo "   gRPC Endpoint : ${ENDPOINT}"
echo "   Update local .syntropy.toml server_url to this endpoint"
echo "=========================================================="
