#!/bin/bash

# Enhanced Payment & Credential Scanner - Deployment Script
# This script automates the deployment process

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to detect OS
detect_os() {
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "linux"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "macos"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then
        echo "windows"
    else
        echo "unknown"
    fi
}

# Function to install system dependencies
install_system_deps() {
    local os=$(detect_os)
    
    print_status "Installing system dependencies for $os..."
    
    case $os in
        "linux")
            if command_exists apt-get; then
                sudo apt-get update
                sudo apt-get install -y python3 python3-pip python3-venv git libpcap-dev
            elif command_exists yum; then
                sudo yum install -y python3 python3-pip git libpcap-devel
            elif command_exists pacman; then
                sudo pacman -S python python-pip git libpcap
            else
                print_warning "Unknown Linux distribution. Please install Python 3, pip, git, and libpcap manually."
            fi
            ;;
        "macos")
            if command_exists brew; then
                brew install python git libpcap
            else
                print_warning "Homebrew not found. Please install Python 3 and git manually."
            fi
            ;;
        "windows")
            print_warning "Windows detected. Please ensure Python 3, git, and WinPcap/Npcap are installed."
            ;;
        *)
            print_warning "Unknown OS. Please install Python 3, pip, git, and libpcap manually."
            ;;
    esac
}

# Function to setup Python environment
setup_python_env() {
    print_status "Setting up Python virtual environment..."
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        print_success "Virtual environment created"
    else
        print_status "Virtual environment already exists"
    fi
    
    # Activate virtual environment
    source venv/bin/activate
    
    # Upgrade pip
    pip install --upgrade pip
    
    # Install requirements
    if [ -f "requirements.txt" ]; then
        print_status "Installing Python dependencies..."
        pip install -r requirements.txt
        print_success "Python dependencies installed"
    else
        print_error "requirements.txt not found!"
        exit 1
    fi
}

# Function to run tests
run_tests() {
    print_status "Running installation tests..."
    
    if [ -f "test_installation.py" ]; then
        python test_installation.py
        if [ $? -eq 0 ]; then
            print_success "All tests passed!"
        else
            print_error "Some tests failed. Please check the output above."
            exit 1
        fi
    else
        print_warning "test_installation.py not found. Skipping tests."
    fi
}

# Function to create desktop shortcut (Linux)
create_desktop_shortcut() {
    if [[ $(detect_os) == "linux" ]]; then
        print_status "Creating desktop shortcut..."
        
        local desktop_file="$HOME/.local/share/applications/credential-scanner.desktop"
        local current_dir=$(pwd)
        
        mkdir -p "$HOME/.local/share/applications"
        
        cat > "$desktop_file" << EOF
[Desktop Entry]
Name=Enhanced Credential Scanner
Comment=Enhanced Payment & Credential Scanner v2.0
Exec=$current_dir/venv/bin/python $current_dir/enhanced_scanner.py
Icon=$current_dir/icon.png
Terminal=false
Type=Application
Categories=Security;Development;
StartupWMClass=enhanced_scanner
EOF
        
        chmod +x "$desktop_file"
        print_success "Desktop shortcut created"
    fi
}

# Function to setup systemd service (Linux)
setup_systemd_service() {
    if [[ $(detect_os) == "linux" ]] && command_exists systemctl; then
        print_status "Setting up systemd service..."
        
        local service_file="/etc/systemd/system/credential-scanner.service"
        local current_dir=$(pwd)
        local current_user=$(whoami)
        
        sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=Enhanced Credential Scanner
After=network.target

[Service]
Type=simple
User=$current_user
WorkingDirectory=$current_dir
Environment=PATH=$current_dir/venv/bin
ExecStart=$current_dir/venv/bin/python $current_dir/enhanced_scanner.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
        
        sudo systemctl daemon-reload
        sudo systemctl enable credential-scanner
        
        print_success "Systemd service created and enabled"
        print_status "Use 'sudo systemctl start credential-scanner' to start the service"
    fi
}

# Function to setup Docker deployment
setup_docker() {
    if command_exists docker; then
        print_status "Setting up Docker deployment..."
        
        # Build Docker image
        docker build -t credential-scanner .
        
        print_success "Docker image built successfully"
        print_status "Use 'docker-compose up' to start with Docker Compose"
        print_status "Or use 'docker run -it --privileged credential-scanner' for direct run"
    else
        print_warning "Docker not found. Skipping Docker setup."
    fi
}

# Function to check permissions
check_permissions() {
    print_status "Checking network capture permissions..."
    
    if [[ $(detect_os) == "linux" ]]; then
        if [ "$EUID" -eq 0 ]; then
            print_success "Running as root - network capture available"
        else
            print_warning "Not running as root. Network capture may require sudo."
            print_status "Consider running: sudo setcap cap_net_raw,cap_net_admin=eip \$(which python3)"
        fi
    elif [[ $(detect_os) == "macos" ]]; then
        print_warning "macOS detected. Network capture may require sudo."
    elif [[ $(detect_os) == "windows" ]]; then
        print_warning "Windows detected. Run as Administrator for network capture."
    fi
}

# Main deployment function
main() {
    echo "🚀 Enhanced Payment & Credential Scanner v2.0 - Deployment Script"
    echo "=================================================================="
    
    # Parse command line arguments
    INSTALL_DEPS=false
    SETUP_SERVICE=false
    SETUP_DOCKER=false
    CREATE_SHORTCUT=false
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --install-deps)
                INSTALL_DEPS=true
                shift
                ;;
            --setup-service)
                SETUP_SERVICE=true
                shift
                ;;
            --setup-docker)
                SETUP_DOCKER=true
                shift
                ;;
            --create-shortcut)
                CREATE_SHORTCUT=true
                shift
                ;;
            --all)
                INSTALL_DEPS=true
                SETUP_SERVICE=true
                SETUP_DOCKER=true
                CREATE_SHORTCUT=true
                shift
                ;;
            -h|--help)
                echo "Usage: $0 [OPTIONS]"
                echo "Options:"
                echo "  --install-deps     Install system dependencies"
                echo "  --setup-service    Setup systemd service (Linux only)"
                echo "  --setup-docker     Setup Docker deployment"
                echo "  --create-shortcut  Create desktop shortcut (Linux only)"
                echo "  --all              Enable all options"
                echo "  -h, --help         Show this help message"
                exit 0
                ;;
            *)
                print_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    # Check if we're in the right directory
    if [ ! -f "enhanced_scanner.py" ]; then
        print_error "enhanced_scanner.py not found. Please run this script from the project directory."
        exit 1
    fi
    
    # Install system dependencies if requested
    if [ "$INSTALL_DEPS" = true ]; then
        install_system_deps
    fi
    
    # Setup Python environment
    setup_python_env
    
    # Run tests
    run_tests
    
    # Check permissions
    check_permissions
    
    # Setup additional components if requested
    if [ "$CREATE_SHORTCUT" = true ]; then
        create_desktop_shortcut
    fi
    
    if [ "$SETUP_SERVICE" = true ]; then
        setup_systemd_service
    fi
    
    if [ "$SETUP_DOCKER" = true ]; then
        setup_docker
    fi
    
    echo ""
    print_success "🎉 Deployment completed successfully!"
    echo ""
    echo "📋 Next Steps:"
    echo "  • Run the application: python enhanced_scanner.py"
    echo "  • Or activate venv first: source venv/bin/activate"
    echo "  • For network capture: run with sudo or as administrator"
    echo "  • Check QUICK_START.md for usage examples"
    echo ""
    echo "🔗 Useful Commands:"
    echo "  • Test installation: python test_installation.py"
    echo "  • Docker run: docker-compose up"
    echo "  • Service start: sudo systemctl start credential-scanner"
    echo ""
    print_status "Happy scanning! 🔍"
}

# Run main function with all arguments
main "$@"
