#!/bin/bash
#
# DLP v2.0 Automated Deployment and Orchestration Script
# Comprehensive deployment automation for all platforms
#

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Global variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/dlp_deployment_$(date +%Y%m%d_%H%M%S).log"
CONFIG_FILE="${SCRIPT_DIR}/deployment_config.yaml"
DLP_VERSION="2.0.0"
DEPLOYMENT_MODE=""
TARGET_PLATFORM=""
KUBERNETES_NAMESPACE="dlp-system"

# ============================================
# Utility Functions
# ============================================

log() {
    echo -e "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

log_info() {
    log "${BLUE}[INFO]${NC} $1"
}

log_success() {
    log "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    log "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    log "${RED}[ERROR]${NC} $1"
}

check_command() {
    if ! command -v "$1" &> /dev/null; then
        log_error "$1 is not installed. Please install it first."
        return 1
    fi
    return 0
}

confirm() {
    read -r -p "$1 [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# ============================================
# Pre-deployment Checks
# ============================================

perform_preflight_checks() {
    log_info "Performing preflight checks..."
    
    local checks_passed=true
    
    # Check OS
    case "$(uname -s)" in
        Linux*)     OS="Linux";;
        Darwin*)    OS="Mac";;
        CYGWIN*|MINGW*|MSYS*) OS="Windows";;
        *)          OS="Unknown";;
    esac
    
    log_info "Detected OS: $OS"
    
    # Check required tools based on deployment mode
    case "$DEPLOYMENT_MODE" in
        kubernetes)
            for cmd in kubectl helm docker; do
                if ! check_command "$cmd"; then
                    checks_passed=false
                fi
            done
            
            # Check Kubernetes connectivity
            if ! kubectl cluster-info &> /dev/null; then
                log_error "Cannot connect to Kubernetes cluster"
                checks_passed=false
            else
                log_info "Kubernetes cluster is accessible"
            fi
            ;;
            
        docker)
            for cmd in docker docker-compose; do
                if ! check_command "$cmd"; then
                    checks_passed=false
                fi
            done
            ;;
            
        baremetal)
            # Platform-specific checks
            case "$TARGET_PLATFORM" in
                linux)
                    # Check kernel version
                    kernel_version=$(uname -r | cut -d. -f1,2)
                    if (( $(echo "$kernel_version < 5.0" | bc -l) )); then
                        log_warning "Kernel version $kernel_version is below recommended 5.0"
                    fi
                    
                    # Check eBPF support
                    if ! grep -q BPF /boot/config-$(uname -r) 2>/dev/null; then
                        log_warning "eBPF support not detected in kernel"
                    fi
                    ;;
                    
                windows)
                    # Check Windows version
                    if ! systeminfo | grep -q "Windows 10\|Windows 11\|Server 2019\|Server 2022"; then
                        log_warning "Unsupported Windows version detected"
                    fi
                    ;;
                    
                macos)
                    # Check macOS version
                    if ! sw_vers -productVersion | grep -qE "^1[1-9]\.|^[2-9][0-9]\."; then
                        log_warning "macOS version below 11.0 detected"
                    fi
                    ;;
            esac
            ;;
    esac
    
    # Check disk space
    available_space=$(df -BG . | awk 'NR==2 {print $4}' | sed 's/G//')
    if [ "$available_space" -lt 20 ]; then
        log_warning "Low disk space: ${available_space}GB available (20GB recommended)"
    fi
    
    # Check memory
    if command -v free &> /dev/null; then
        available_memory=$(free -g | awk 'NR==2 {print $7}')
        if [ "$available_memory" -lt 8 ]; then
            log_warning "Low memory: ${available_memory}GB available (8GB recommended)"
        fi
    fi
    
    if [ "$checks_passed" = true ]; then
        log_success "All preflight checks passed"
        return 0
    else
        log_error "Some preflight checks failed"
        return 1
    fi
}

# ============================================
# Configuration Management
# ============================================

generate_config() {
    log_info "Generating deployment configuration..."
    
    cat > "$CONFIG_FILE" <<EOF
# DLP v2.0 Deployment Configuration
version: ${DLP_VERSION}
deployment:
  mode: ${DEPLOYMENT_MODE}
  platform: ${TARGET_PLATFORM}
  
# Core Services Configuration
services:
  api_gateway:
    replicas: 3
    resources:
      requests:
        memory: "512Mi"
        cpu: "500m"
      limits:
        memory: "2Gi"
        cpu: "2000m"
    
  policy_service:
    replicas: 2
    database:
      type: postgresql
      storage: 50Gi
    
  detection_service:
    replicas: 5
    ml_models:
      - name: text_classifier
        version: v3.2
        device: auto
      - name: pii_detector
        version: v4.1
        device: cpu
    
  analytics_service:
    replicas: 3
    storage:
      mongodb: 100Gi
      influxdb: 50Gi

# Security Configuration
security:
  tls:
    enabled: true
    cert_manager: true
  
  encryption:
    at_rest: true
    algorithm: AES-256-GCM
    key_rotation_days: 90
  
  authentication:
    method: oauth2
    providers:
      - name: okta
        enabled: true
      - name: azure_ad
        enabled: false

# Monitoring Configuration
monitoring:
  prometheus:
    enabled: true
    retention: 30d
    storage: 100Gi
  
  grafana:
    enabled: true
    dashboards:
      - dlp-overview
      - dlp-performance
      - dlp-security
  
  alerting:
    enabled: true
    channels:
      - type: email
        recipients:
          - security@company.com
      - type: slack
        webhook: \${SLACK_WEBHOOK_URL}

# Agent Configuration
agents:
  auto_update: true
  heartbeat_interval: 60s
  log_level: info
  
  linux:
    ebpf_enabled: true
    kernel_module: true
    
  windows:
    wfp_driver: true
    minifilter: true
    
  macos:
    system_extension: true
    network_extension: true

# Backup Configuration
backup:
  enabled: true
  schedule: "0 2 * * *"  # 2 AM daily
  retention_days: 30
  destinations:
    - type: s3
      bucket: dlp-backups
      region: us-east-1
EOF
    
    log_success "Configuration file generated: $CONFIG_FILE"
}

# ============================================
# Kubernetes Deployment
# ============================================

deploy_kubernetes() {
    log_info "Starting Kubernetes deployment..."
    
    # Create namespace
    log_info "Creating namespace: $KUBERNETES_NAMESPACE"
    kubectl create namespace "$KUBERNETES_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
    
    # Install cert-manager for TLS
    if confirm "Install cert-manager for automatic TLS certificate management?"; then
        log_info "Installing cert-manager..."
        kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
        
        # Wait for cert-manager to be ready
        kubectl wait --for=condition=ready pod -l app.kubernetes.io/instance=cert-manager -n cert-manager --timeout=300s
    fi
    
    # Create secrets
    create_kubernetes_secrets
    
    # Deploy using Helm
    if [ -d "${SCRIPT_DIR}/helm/dlp-v2" ]; then
        log_info "Installing DLP v2.0 using Helm..."
        
        helm upgrade --install dlp-v2 "${SCRIPT_DIR}/helm/dlp-v2" \
            --namespace "$KUBERNETES_NAMESPACE" \
            --values "$CONFIG_FILE" \
            --timeout 10m \
            --wait
            
        log_success "Helm deployment completed"
    else
        # Deploy using kubectl
        log_info "Installing DLP v2.0 using kubectl..."
        deploy_kubernetes_manifests
    fi
    
    # Deploy agents as DaemonSet
    deploy_kubernetes_agents
    
    # Setup monitoring
    if confirm "Deploy Prometheus and Grafana for monitoring?"; then
        deploy_kubernetes_monitoring
    fi
    
    # Verify deployment
    verify_kubernetes_deployment
}

create_kubernetes_secrets() {
    log_info "Creating Kubernetes secrets..."
    
    # Database passwords
    kubectl create secret generic dlp-db-secrets \
        --namespace="$KUBERNETES_NAMESPACE" \
        --from-literal=postgres-password="$(openssl rand -base64 32)" \
        --from-literal=mongodb-password="$(openssl rand -base64 32)" \
        --from-literal=redis-password="$(openssl rand -base64 32)" \
        --dry-run=client -o yaml | kubectl apply -f -
    
    # API keys
    kubectl create secret generic dlp-api-keys \
        --namespace="$KUBERNETES_NAMESPACE" \
        --from-literal=ml-api-key="$(openssl rand -hex 32)" \
        --from-literal=encryption-key="$(openssl rand -base64 32)" \
        --dry-run=client -o yaml | kubectl apply -f -
}

deploy_kubernetes_manifests() {
    log_info "Deploying Kubernetes manifests..."
    
    # Generate manifests
    cat > "${SCRIPT_DIR}/k8s-deployment.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: dlp-config
  namespace: ${KUBERNETES_NAMESPACE}
data:
  config.yaml: |
    ${CONFIG_CONTENT}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: dlp-api-gateway
  namespace: ${KUBERNETES_NAMESPACE}
spec:
  replicas: 3
  selector:
    matchLabels:
      app: dlp-api-gateway
  template:
    metadata:
      labels:
        app: dlp-api-gateway
    spec:
      containers:
      - name: gateway
        image: dlp/gateway:${DLP_VERSION}
        ports:
        - containerPort: 8443
          name: https
        env:
        - name: CONFIG_PATH
          value: /etc/dlp/config.yaml
        volumeMounts:
        - name: config
          mountPath: /etc/dlp
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "2Gi"
            cpu: "2000m"
      volumes:
      - name: config
        configMap:
          name: dlp-config
---
apiVersion: v1
kind: Service
metadata:
  name: dlp-api-gateway
  namespace: ${KUBERNETES_NAMESPACE}
spec:
  selector:
    app: dlp-api-gateway
  ports:
  - port: 443
    targetPort: 8443
    protocol: TCP
  type: LoadBalancer
EOF
    
    # Apply manifests
    kubectl apply -f "${SCRIPT_DIR}/k8s-deployment.yaml"
}

deploy_kubernetes_agents() {
    log_info "Deploying DLP agents as DaemonSet..."
    
    cat > "${SCRIPT_DIR}/k8s-agents.yaml" <<'EOF'
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: dlp-agent
  namespace: ${KUBERNETES_NAMESPACE}
spec:
  selector:
    matchLabels:
      app: dlp-agent
  template:
    metadata:
      labels:
        app: dlp-agent
    spec:
      hostNetwork: true
      hostPID: true
      containers:
      - name: dlp-agent
        image: dlp/agent:${DLP_VERSION}
        securityContext:
          privileged: true
          capabilities:
            add:
            - SYS_ADMIN
            - NET_ADMIN
            - SYS_PTRACE
        env:
        - name: NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: DLP_SERVER
          value: "dlp-api-gateway.${KUBERNETES_NAMESPACE}.svc.cluster.local"
        volumeMounts:
        - name: host-root
          mountPath: /host
          readOnly: true
        - name: sys
          mountPath: /sys
        - name: docker-sock
          mountPath: /var/run/docker.sock
      volumes:
      - name: host-root
        hostPath:
          path: /
      - name: sys
        hostPath:
          path: /sys
      - name: docker-sock
        hostPath:
          path: /var/run/docker.sock
EOF
    
    kubectl apply -f "${SCRIPT_DIR}/k8s-agents.yaml"
}

deploy_kubernetes_monitoring() {
    log_info "Deploying monitoring stack..."
    
    # Add Prometheus Helm repo
    helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
    helm repo update
    
    # Install Prometheus stack
    helm upgrade --install prometheus prometheus-community/kube-prometheus-stack \
        --namespace "$KUBERNETES_NAMESPACE" \
        --set prometheus.prometheusSpec.retention=30d \
        --set prometheus.prometheusSpec.storageSpec.volumeClaimTemplate.spec.resources.requests.storage=100Gi
    
    # Create DLP dashboards
    create_grafana_dashboards
}

verify_kubernetes_deployment() {
    log_info "Verifying Kubernetes deployment..."
    
    # Check pod status
    kubectl get pods -n "$KUBERNETES_NAMESPACE"
    
    # Wait for all pods to be ready
    kubectl wait --for=condition=ready pod -l app=dlp-api-gateway -n "$KUBERNETES_NAMESPACE" --timeout=300s
    
    # Get service endpoints
    log_info "Service endpoints:"
    kubectl get svc -n "$KUBERNETES_NAMESPACE"
    
    # Run smoke tests
    run_smoke_tests_kubernetes
}

# ============================================
# Docker Deployment
# ============================================

deploy_docker() {
    log_info "Starting Docker deployment..."
    
    # Generate docker-compose.yml
    generate_docker_compose
    
    # Pull images
    log_info "Pulling Docker images..."
    docker-compose -f "${SCRIPT_DIR}/docker-compose.yml" pull
    
    # Start services
    log_info "Starting DLP services..."
    docker-compose -f "${SCRIPT_DIR}/docker-compose.yml" up -d
    
    # Wait for services to be healthy
    wait_for_docker_services
    
    # Run initialization
    initialize_docker_deployment
    
    # Verify deployment
    verify_docker_deployment
}

generate_docker_compose() {
    log_info "Generating docker-compose.yml..."
    
    cat > "${SCRIPT_DIR}/docker-compose.yml" <<'EOF'
version: '3.8'

services:
  # API Gateway
  gateway:
    image: dlp/gateway:${DLP_VERSION}
    ports:
      - "443:8443"
      - "80:8080"
    environment:
      - CONFIG_PATH=/etc/dlp/config.yaml
    volumes:
      - ./config:/etc/dlp:ro
      - ./certs:/etc/dlp/certs:ro
    depends_on:
      - policy-service
      - detection-service
    restart: unless-stopped
    
  # Policy Service
  policy-service:
    image: dlp/policy-service:${DLP_VERSION}
    environment:
      - DATABASE_URL=postgresql://dlp:${DB_PASSWORD}@postgres:5432/dlp
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
    depends_on:
      - postgres
      - redis
    restart: unless-stopped
    
  # Detection Service
  detection-service:
    image: dlp/detection-service:${DLP_VERSION}
    deploy:
      replicas: 3
    environment:
      - ML_MODELS_PATH=/models
      - REDIS_URL=redis://:${REDIS_PASSWORD}@redis:6379
    volumes:
      - ./models:/models:ro
    depends_on:
      - redis
    restart: unless-stopped
    
  # Analytics Service
  analytics-service:
    image: dlp/analytics-service:${DLP_VERSION}
    environment:
      - MONGODB_URL=mongodb://dlp:${MONGO_PASSWORD}@mongodb:27017/dlp
      - INFLUXDB_URL=http://influxdb:8086
    depends_on:
      - mongodb
      - influxdb
    restart: unless-stopped
    
  # Databases
  postgres:
    image: postgres:14-alpine
    environment:
      - POSTGRES_DB=dlp
      - POSTGRES_USER=dlp
      - POSTGRES_PASSWORD=${DB_PASSWORD}
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped
    
  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD} --appendonly yes
    volumes:
      - redis_data:/data
    restart: unless-stopped
    
  mongodb:
    image: mongo:5
    environment:
      - MONGO_INITDB_ROOT_USERNAME=dlp
      - MONGO_INITDB_ROOT_PASSWORD=${MONGO_PASSWORD}
      - MONGO_INITDB_DATABASE=dlp
    volumes:
      - mongo_data:/data/db
    restart: unless-stopped
    
  influxdb:
    image: influxdb:2.0
    environment:
      - INFLUXDB_DB=dlp
      - INFLUXDB_ADMIN_USER=admin
      - INFLUXDB_ADMIN_PASSWORD=${INFLUX_PASSWORD}
    volumes:
      - influx_data:/var/lib/influxdb2
    restart: unless-stopped
    
  # Monitoring
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/usr/share/prometheus/console_libraries'
      - '--web.console.templates=/usr/share/prometheus/consoles'
    restart: unless-stopped
    
  grafana:
    image: grafana/grafana:latest
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=${GRAFANA_PASSWORD}
      - GF_INSTALL_PLUGINS=grafana-clock-panel,grafana-simple-json-datasource
    volumes:
      - grafana_data:/var/lib/grafana
      - ./grafana/dashboards:/etc/grafana/provisioning/dashboards
      - ./grafana/datasources:/etc/grafana/provisioning/datasources
    ports:
      - "3000:3000"
    restart: unless-stopped

volumes:
  postgres_data:
  redis_data:
  mongo_data:
  influx_data:
  prometheus_data:
  grafana_data:

networks:
  default:
    name: dlp_network
EOF
    
    # Generate .env file
    cat > "${SCRIPT_DIR}/.env" <<EOF
DLP_VERSION=${DLP_VERSION}
DB_PASSWORD=$(openssl rand -base64 32)
REDIS_PASSWORD=$(openssl rand -base64 32)
MONGO_PASSWORD=$(openssl rand -base64 32)
INFLUX_PASSWORD=$(openssl rand -base64 32)
GRAFANA_PASSWORD=$(openssl rand -base64 32)
EOF
    
    log_success "Docker Compose configuration generated"
}

wait_for_docker_services() {
    log_info "Waiting for services to be healthy..."
    
    local max_attempts=60
    local attempt=0
    
    while [ $attempt -lt $max_attempts ]; do
        if docker-compose -f "${SCRIPT_DIR}/docker-compose.yml" ps | grep -q "unhealthy\|starting"; then
            log_info "Services still starting... (attempt $((attempt + 1))/$max_attempts)"
            sleep 5
            ((attempt++))
        else
            log_success "All services are healthy"
            return 0
        fi
    done
    
    log_error "Services failed to become healthy within timeout"
    return 1
}

# ============================================
# Bare Metal Deployment
# ============================================

deploy_baremetal() {
    log_info "Starting bare metal deployment for $TARGET_PLATFORM..."
    
    case "$TARGET_PLATFORM" in
        linux)
            deploy_baremetal_linux
            ;;
        windows)
            deploy_baremetal_windows
            ;;
        macos)
            deploy_baremetal_macos
            ;;
        *)
            log_error "Unsupported platform: $TARGET_PLATFORM"
            return 1
            ;;
    esac
}

deploy_baremetal_linux() {
    log_info "Deploying on Linux..."
    
    # Check distribution
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        log_info "Detected distribution: $DISTRO"
    fi
    
    # Install dependencies
    case "$DISTRO" in
        ubuntu|debian)
            log_info "Installing dependencies..."
            sudo apt-get update
            sudo apt-get install -y \
                build-essential \
                linux-headers-$(uname -r) \
                libbpf-dev \
                libssl-dev \
                libpcap-dev \
                postgresql-client \
                redis-tools
            ;;
        rhel|centos|fedora)
            log_info "Installing dependencies..."
            sudo yum install -y \
                gcc \
                kernel-devel \
                libbpf-devel \
                openssl-devel \
                libpcap-devel \
                postgresql \
                redis
            ;;
    esac
    
    # Install DLP binaries
    install_dlp_binaries_linux
    
    # Configure services
    configure_systemd_services
    
    # Install kernel modules
    if confirm "Install kernel modules for enhanced monitoring?"; then
        install_kernel_modules
    fi
    
    # Setup eBPF programs
    setup_ebpf_programs
    
    # Start services
    start_linux_services
}

install_dlp_binaries_linux() {
    log_info "Installing DLP binaries..."
    
    # Create directories
    sudo mkdir -p /opt/dlp/{bin,config,data,logs,models}
    sudo mkdir -p /etc/dlp
    sudo mkdir -p /var/lib/dlp
    
    # Download and extract binaries
    if [ -f "${SCRIPT_DIR}/dlp-linux-${DLP_VERSION}.tar.gz" ]; then
        sudo tar -xzf "${SCRIPT_DIR}/dlp-linux-${DLP_VERSION}.tar.gz" -C /opt/dlp/bin/
    else
        log_warning "Binary package not found, building from source..."
        build_from_source_linux
    fi
    
    # Set permissions
    sudo chmod +x /opt/dlp/bin/*
    sudo chown -R dlp:dlp /opt/dlp /var/lib/dlp
}

configure_systemd_services() {
    log_info "Configuring systemd services..."
    
    # Create systemd service files
    for service in policy detection analytics agent; do
        cat > "/tmp/dlp-${service}.service" <<EOF
[Unit]
Description=DLP ${service^} Service
After=network.target

[Service]
Type=notify
User=dlp
Group=dlp
ExecStart=/opt/dlp/bin/dlp-${service}
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
EOF
        
        sudo mv "/tmp/dlp-${service}.service" /etc/systemd/system/
    done
    
    sudo systemctl daemon-reload
}

setup_ebpf_programs() {
    log_info "Setting up eBPF programs..."
    
    # Load eBPF programs
    sudo /opt/dlp/bin/dlp-ebpf-loader \
        --program network_monitor \
        --program file_monitor \
        --program process_monitor
    
    # Verify eBPF programs
    if command -v bpftool &> /dev/null; then
        log_info "Loaded eBPF programs:"
        sudo bpftool prog show | grep dlp
    fi
}

start_linux_services() {
    log_info "Starting DLP services..."
    
    # Create dlp user if not exists
    if ! id -u dlp &> /dev/null; then
        sudo useradd -r -s /bin/false -d /var/lib/dlp dlp
    fi
    
    # Start services in order
    for service in policy detection analytics agent; do
        log_info "Starting dlp-${service}..."
        sudo systemctl enable dlp-${service}
        sudo systemctl start dlp-${service}
        
        # Wait for service to be ready
        sleep 2
        
        if sudo systemctl is-active --quiet dlp-${service}; then
            log_success "dlp-${service} started successfully"
        else
            log_error "Failed to start dlp-${service}"
            sudo journalctl -u dlp-${service} -n 50
        fi
    done
}

deploy_baremetal_windows() {
    log_info "Deploying on Windows..."
    
    # Check if running as Administrator
    net session >nul 2>&1
    if [ $? -ne 0 ]; then
        log_error "This script must be run as Administrator"
        return 1
    fi
    
    # Install prerequisites
    log_info "Installing prerequisites..."
    
    # Install Visual C++ Redistributables
    if [ ! -f "C:/Windows/System32/vcruntime140.dll" ]; then
        log_info "Installing Visual C++ Redistributables..."
        curl -L -o vc_redist.x64.exe https://aka.ms/vs/17/release/vc_redist.x64.exe
        ./vc_redist.x64.exe /quiet /norestart
    fi
    
    # Install DLP
    if [ -f "${SCRIPT_DIR}/DLPAgent-${DLP_VERSION}.msi" ]; then
        log_info "Installing DLP Agent..."
        msiexec /i "${SCRIPT_DIR}/DLPAgent-${DLP_VERSION}.msi" /quiet /norestart
    else
        log_error "DLP Agent installer not found"
        return 1
    fi
    
    # Install WFP driver
    install_wfp_driver_windows
    
    # Configure Windows services
    configure_windows_services
    
    # Start services
    start_windows_services
}

install_wfp_driver_windows() {
    log_info "Installing Windows Filtering Platform driver..."
    
    # Install driver
    if [ -f "/opt/dlp/drivers/DLPFilter.sys" ]; then
        # Create driver service
        sc create DLPFilter type= kernel binPath= "C:\\Program Files\\DLP\\drivers\\DLPFilter.sys"
        
        # Start driver
        sc start DLPFilter
        
        # Configure autostart
        sc config DLPFilter start= auto
    fi
}

configure_windows_services() {
    log_info "Configuring Windows services..."
    
    # Configure DLP Agent service
    sc config DLPAgent start= auto
    sc failure DLPAgent reset= 86400 actions= restart/5000/restart/10000/restart/30000
    
    # Set service dependencies
    sc config DLPAgent depend= Tcpip/Afd/DLPFilter
}

start_windows_services() {
    log_info "Starting Windows services..."
    
    # Start DLP Agent service
    net start DLPAgent
    
    # Verify service status
    sc query DLPAgent | grep -q "RUNNING"
    if [ $? -eq 0 ]; then
        log_success "DLP Agent service started successfully"
    else
        log_error "Failed to start DLP Agent service"
        # Check event logs
        wevtutil qe Application /c:10 /f:text /q:"*[System[Provider[@Name='DLPAgent']]]"
    fi
}

deploy_baremetal_macos() {
    log_info "Deploying on macOS..."
    
    # Check macOS version
    macos_version=$(sw_vers -productVersion)
    log_info "macOS version: $macos_version"
    
    # Install using pkg installer
    if [ -f "${SCRIPT_DIR}/DLPAgent-${DLP_VERSION}.pkg" ]; then
        log_info "Installing DLP Agent..."
        sudo installer -pkg "${SCRIPT_DIR}/DLPAgent-${DLP_VERSION}.pkg" -target /
    else
        log_error "DLP Agent installer not found"
        return 1
    fi
    
    # Load system extension
    load_macos_system_extension
    
    # Configure launch daemon
    configure_macos_launch_daemon
    
    # Start services
    start_macos_services
}

load_macos_system_extension() {
    log_info "Loading system extension..."
    
    # Request user approval for system extension
    log_warning "System extension requires user approval in System Preferences"
    log_warning "Please go to System Preferences > Security & Privacy to allow"
    
    # Load extension
    sudo systemextensionsctl install /Applications/DLPAgent.app/Contents/Library/SystemExtensions/com.company.dlp.networkextension
}

configure_macos_launch_daemon() {
    log_info "Configuring launch daemon..."
    
    # Create launch daemon plist
    sudo tee /Library/LaunchDaemons/com.company.dlpagent.plist > /dev/null <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.company.dlpagent</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/DLPAgent.app/Contents/MacOS/DLPAgent</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/dlp/agent.err</string>
    <key>StandardOutPath</key>
    <string>/var/log/dlp/agent.out</string>
</dict>
</plist>
EOF
    
    # Set permissions
    sudo chmod 644 /Library/LaunchDaemons/com.company.dlpagent.plist
    sudo chown root:wheel /Library/LaunchDaemons/com.company.dlpagent.plist
}

start_macos_services() {
    log_info "Starting macOS services..."
    
    # Load launch daemon
    sudo launchctl load /Library/LaunchDaemons/com.company.dlpagent.plist
    
    # Verify service is running
    if sudo launchctl list | grep -q com.company.dlpagent; then
        log_success "DLP Agent started successfully"
    else
        log_error "Failed to start DLP Agent"
        # Check logs
        tail -n 50 /var/log/dlp/agent.err
    fi
}

# ============================================
# Post-Deployment Tasks
# ============================================

post_deployment_tasks() {
    log_info "Running post-deployment tasks..."
    
    # Initialize database
    initialize_database
    
    # Load default policies
    load_default_policies
    
    # Configure integrations
    configure_integrations
    
    # Run health checks
    run_health_checks
    
    # Generate access credentials
    generate_access_credentials
    
    # Create initial admin user
    create_admin_user
    
    # Setup backup schedule
    setup_backup_schedule
}

initialize_database() {
    log_info "Initializing database..."
    
    case "$DEPLOYMENT_MODE" in
        kubernetes)
            kubectl exec -n "$KUBERNETES_NAMESPACE" deployment/policy-service -- \
                dlp-cli db init
            ;;
        docker)
            docker-compose exec policy-service dlp-cli db init
            ;;
        baremetal)
            /opt/dlp/bin/dlp-cli db init
            ;;
    esac
}

load_default_policies() {
    log_info "Loading default policies..."
    
    # Download default policy pack
    if [ ! -f "${SCRIPT_DIR}/default-policies.yaml" ]; then
        curl -L -o "${SCRIPT_DIR}/default-policies.yaml" \
            https://raw.githubusercontent.com/company/dlp-policies/main/default-policies.yaml
    fi
    
    # Import policies
    case "$DEPLOYMENT_MODE" in
        kubernetes)
            kubectl cp "${SCRIPT_DIR}/default-policies.yaml" \
                "$KUBERNETES_NAMESPACE/policy-service-0:/tmp/policies.yaml"
            kubectl exec -n "$KUBERNETES_NAMESPACE" deployment/policy-service -- \
                dlp-cli policy import /tmp/policies.yaml
            ;;
        docker)
            docker cp "${SCRIPT_DIR}/default-policies.yaml" \
                dlp_policy-service_1:/tmp/policies.yaml
            docker-compose exec policy-service \
                dlp-cli policy import /tmp/policies.yaml
            ;;
        baremetal)
            /opt/dlp/bin/dlp-cli policy import "${SCRIPT_DIR}/default-policies.yaml"
            ;;
    esac
}

run_health_checks() {
    log_info "Running health checks..."
    
    local all_healthy=true
    
    # Check API Gateway
    if ! curl -k -s https://localhost/health > /dev/null; then
        log_error "API Gateway health check failed"
        all_healthy=false
    else
        log_success "API Gateway is healthy"
    fi
    
    # Check services based on deployment mode
    case "$DEPLOYMENT_MODE" in
        kubernetes)
            # Check pod status
            unhealthy_pods=$(kubectl get pods -n "$KUBERNETES_NAMESPACE" --no-headers | grep -v Running | wc -l)
            if [ "$unhealthy_pods" -gt 0 ]; then
                log_error "$unhealthy_pods pods are not running"
                all_healthy=false
            fi
            ;;
        docker)
            # Check container status
            unhealthy_containers=$(docker-compose ps | grep -v Up | grep -v Name | wc -l)
            if [ "$unhealthy_containers" -gt 0 ]; then
                log_error "$unhealthy_containers containers are not running"
                all_healthy=false
            fi
            ;;
        baremetal)
            # Check systemd services
            for service in policy detection analytics agent; do
                if ! systemctl is-active --quiet dlp-${service}; then
                    log_error "dlp-${service} is not running"
                    all_healthy=false
                fi
            done
            ;;
    esac
    
    if [ "$all_healthy" = true ]; then
        log_success "All health checks passed"
        return 0
    else
        log_error "Some health checks failed"
        return 1
    fi
}

generate_access_credentials() {
    log_info "Generating access credentials..."
    
    # Generate API key
    API_KEY=$(openssl rand -hex 32)
    
    # Generate admin password
    ADMIN_PASSWORD=$(openssl rand -base64 16)
    
    # Save credentials
    cat > "${SCRIPT_DIR}/dlp-credentials.txt" <<EOF
DLP v2.0 Access Credentials
==========================

API Endpoint: https://localhost/api/v2
API Key: ${API_KEY}

Admin Console: https://localhost
Username: admin
Password: ${ADMIN_PASSWORD}

Grafana Dashboard: https://localhost:3000
Username: admin
Password: ${GRAFANA_PASSWORD:-admin}

Note: Please change these credentials after first login.
EOF
    
    chmod 600 "${SCRIPT_DIR}/dlp-credentials.txt"
    log_success "Credentials saved to: ${SCRIPT_DIR}/dlp-credentials.txt"
}

# ============================================
# Testing and Validation
# ============================================

run_smoke_tests() {
    log_info "Running smoke tests..."
    
    # Test policy creation
    test_policy_creation
    
    # Test data detection
    test_data_detection
    
    # Test agent connectivity
    test_agent_connectivity
    
    # Test integrations
    test_integrations
}

test_policy_creation() {
    log_info "Testing policy creation..."
    
    # Create test policy
    TEST_POLICY=$(cat <<'EOF'
{
  "name": "Test Policy",
  "description": "Smoke test policy",
  "enabled": true,
  "patterns": [
    {
      "name": "test_pattern",
      "regex": "TEST-[0-9]{4}"
    }
  ],
  "actions": ["log"]
}
EOF
)
    
    # Create policy via API
    response=$(curl -k -s -X POST https://localhost/api/v2/policies \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$TEST_POLICY")
    
    if echo "$response" | grep -q '"id"'; then
        log_success "Policy creation test passed"
    else
        log_error "Policy creation test failed: $response"
    fi
}

test_data_detection() {
    log_info "Testing data detection..."
    
    # Test data with sensitive pattern
    TEST_DATA='{"text": "Credit card: 4532-1234-5678-9012"}'
    
    response=$(curl -k -s -X POST https://localhost/api/v2/scan \
        -H "Authorization: Bearer ${API_KEY}" \
        -H "Content-Type: application/json" \
        -d "$TEST_DATA")
    
    if echo "$response" | grep -q '"detected":true'; then
        log_success "Data detection test passed"
    else
        log_error "Data detection test failed: $response"
    fi
}

# ============================================
# Cleanup Functions
# ============================================

cleanup_deployment() {
    log_warning "Cleaning up deployment..."
    
    if ! confirm "Are you sure you want to remove the DLP deployment?"; then
        log_info "Cleanup cancelled"
        return
    fi
    
    case "$DEPLOYMENT_MODE" in
        kubernetes)
            kubectl delete namespace "$KUBERNETES_NAMESPACE"
            ;;
        docker)
            docker-compose -f "${SCRIPT_DIR}/docker-compose.yml" down -v
            ;;
        baremetal)
            case "$TARGET_PLATFORM" in
                linux)
                    sudo systemctl stop dlp-*
                    sudo systemctl disable dlp-*
                    sudo rm -rf /opt/dlp /etc/dlp /var/lib/dlp
                    ;;
                windows)
                    net stop DLPAgent
                    sc delete DLPAgent
                    sc delete DLPFilter
                    ;;
                macos)
                    sudo launchctl unload /Library/LaunchDaemons/com.company.dlpagent.plist
                    sudo rm -rf /Applications/DLPAgent.app
                    ;;
            esac
            ;;
    esac
    
    log_success "Cleanup completed"
}

# ============================================
# Main Execution
# ============================================

show_usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

DLP v2.0 Automated Deployment Script

OPTIONS:
    -m, --mode MODE         Deployment mode: kubernetes, docker, baremetal (required)
    -p, --platform PLATFORM Target platform: linux, windows, macos (required for baremetal)
    -c, --config FILE       Configuration file (default: deployment_config.yaml)
    -n, --namespace NS      Kubernetes namespace (default: dlp-system)
    -v, --version VERSION   DLP version to deploy (default: 2.0.0)
    --cleanup               Remove existing deployment
    --dry-run               Show what would be done without executing
    -h, --help              Show this help message

EXAMPLES:
    # Deploy to Kubernetes
    $0 --mode kubernetes

    # Deploy using Docker Compose
    $0 --mode docker

    # Deploy on bare metal Linux
    $0 --mode baremetal --platform linux

    # Clean up deployment
    $0 --mode kubernetes --cleanup
EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -m|--mode)
                DEPLOYMENT_MODE="$2"
                shift 2
                ;;
            -p|--platform)
                TARGET_PLATFORM="$2"
                shift 2
                ;;
            -c|--config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            -n|--namespace)
                KUBERNETES_NAMESPACE="$2"
                shift 2
                ;;
            -v|--version)
                DLP_VERSION="$2"
                shift 2
                ;;
            --cleanup)
                CLEANUP_MODE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_usage
                exit 1
                ;;
        esac
    done
}

validate_arguments() {
    if [ -z "$DEPLOYMENT_MODE" ]; then
        log_error "Deployment mode is required"
        show_usage
        exit 1
    fi
    
    if [ "$DEPLOYMENT_MODE" = "baremetal" ] && [ -z "$TARGET_PLATFORM" ]; then
        log_error "Target platform is required for bare metal deployment"
        show_usage
        exit 1
    fi
    
    # Validate deployment mode
    case "$DEPLOYMENT_MODE" in
        kubernetes|docker|baremetal)
            ;;
        *)
            log_error "Invalid deployment mode: $DEPLOYMENT_MODE"
            show_usage
            exit 1
            ;;
    esac
    
    # Validate platform
    if [ -n "$TARGET_PLATFORM" ]; then
        case "$TARGET_PLATFORM" in
            linux|windows|macos)
                ;;
            *)
                log_error "Invalid platform: $TARGET_PLATFORM"
                show_usage
                exit 1
                ;;
        esac
    fi
}

main() {
    log_info "DLP v2.0 Deployment Script Started"
    log_info "Version: $DLP_VERSION"
    log_info "Deployment Mode: $DEPLOYMENT_MODE"
    
    if [ "$CLEANUP_MODE" = true ]; then
        cleanup_deployment
        exit 0
    fi
    
    # Run preflight checks
    if ! perform_preflight_checks; then
        log_error "Preflight checks failed. Please fix the issues and try again."
        exit 1
    fi
    
    # Generate configuration if not exists
    if [ ! -f "$CONFIG_FILE" ]; then
        generate_config
    fi
    
    # Start deployment based on mode
    case "$DEPLOYMENT_MODE" in
        kubernetes)
            deploy_kubernetes
            ;;
        docker)
            deploy_docker
            ;;
        baremetal)
            deploy_baremetal
            ;;
    esac
    
    # Run post-deployment tasks
    post_deployment_tasks
    
    # Run smoke tests
    run_smoke_tests
    
    log_success "DLP v2.0 deployment completed successfully!"
    log_info "Access credentials saved to: ${SCRIPT_DIR}/dlp-credentials.txt"
    log_info "Deployment log saved to: $LOG_FILE"
}

# Parse command line arguments
parse_arguments "$@"

# Validate arguments
validate_arguments

# Run main function
main
