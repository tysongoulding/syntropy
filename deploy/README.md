# Syntropy Cloud Deployment Options

Syntropy Cloud services (`syntropy-gateway` and `syntropy-orchestrator`) can be deployed to **Proxmox VE**, **AWS**, or **Google Cloud Platform (GCP)**.

---

## 1. Proxmox VE (Self-Hosted LXC Container)

Deploy directly from the Proxmox VE Host Shell (`pve-shell`):

```bash
# Upload or curl deploy script to Proxmox VE host
bash deploy/proxmox/deploy-lxc.sh [CONTAINER_ID] [HOSTNAME] [STORAGE_POOL]
```

**Features:**
- Automatic Debian 12 LXC container provisioning (`pct create`).
- Docker CE engine installed with nesting enabled (`features: nesting=1`).
- Runs `syntropy-gateway` listening on port `50051`.

---

## 2. AWS (CloudFormation + ECS Fargate + NLB)

Deploy via AWS CloudFormation with a dedicated Network Load Balancer (NLB) for high-performance HTTP/2 gRPC traffic:

```bash
aws cloudformation deploy \
  --template-file deploy/aws/cloudformation.yaml \
  --stack-name syntropy-cloud-prod \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides EnvironmentName=syntropy-prod
```

**Features:**
- **Network Load Balancer (NLB)**: Layer-4 passthrough preserving persistent HTTP/2 gRPC streams on port `50051`.
- **ECS Fargate**: Serverless containers running in isolated VPC subnets with auto-recovery.
- **CloudWatch Logs**: Centralized structured logging for gateway events.

---

## 3. Google Cloud Platform (GCP)

GCP provides two native deployment paths:

### Option A: Serverless Cloud Run (Recommended for GCP)
Google Cloud Run natively supports end-to-end HTTP/2 and bidirectional streaming gRPC:

```bash
bash deploy/gcp/deploy-cloudrun.sh [GCP_PROJECT_ID] [REGION]
```

### Option B: Google Cloud Deployment Manager (GCP equivalent to CloudFormation)
Deploy declarative infrastructure using GCP Deployment Manager:

```bash
gcloud deployment-manager deployments create syntropy-cloud \
  --config deploy/gcp/deployment-manager.yaml
```
