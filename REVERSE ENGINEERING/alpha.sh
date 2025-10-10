#!/bin/bash

# REVERSE ENGINEERING & DEVELOPMENT OPERATIONS PLATFORM
# Because sometimes you need to take shit apart and put it back together
# From binary analysis to full-stack development in one messy package

set -e

# Configuration - the boring part
USER_HOME="/home/$SUDO_USER"
DEV_ROOT="$USER_HOME/dev_ops"
REVERSE_ENG="$DEV_ROOT/reverse_engineering"
DEV_TOOLS="$DEV_ROOT/development"
ANALYSIS_WORKSPACE="$DEV_ROOT/analysis"

# Colors for when we feel fancy
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[-]${NC} $1"; }

# Root check - because we're not animals
[ "$EUID" -eq 0 ] || { error "Need root. Stop being a peasant."; exit 1; }

# ============================================================================
# WORKSPACE SETUP - Organized chaos
# ============================================================================

log "Building the digital workshop"
mkdir -p {$REVERSE_ENG/{binaries,analysis,tools,scripts},$DEV_TOOLS/{src,bin,lib,scripts},$ANALYSIS_WORKSPACE/{malware,samples,reports}}

# ============================================================================
# SYSTEM DEPENDENCIES - The foundation of our digital empire
# ============================================================================

log "Installing system dependencies"
{
    apt update -qq
    apt upgrade -y -qq
    
    # Reverse engineering essentials
    apt install -y -qq \
        build-essential cmake ninja-build \
        gcc g++ gdb gdb-multiarch \
        clang clang-format lldb \
        python3 python3-pip python3-venv python3-dev \
        git curl wget vim tmux htop \
        binutils hexedit hexcurse \
        file strings binwalk foremost \
        patchelf ltrace strace \
        radare2 cutter \
        angr \
        jq xmlstarlet sqlite3
    
    # Development tools
    apt install -y -qq \
        nodejs npm yarn \
        golang-go rustc cargo \
        openjdk-17-jdk openjdk-17-jre \
        ruby ruby-dev perl \
        docker.io docker-compose \
        nasm yasm \
        valgrind kcachegrind \
        gnuplot graphviz
    
    # Analysis and forensics
    apt install -y -qq \
        wireshark tshark tcpdump \
        nmap masscan netdiscover \
        exiftool exiv2 \
        steghide outguess \
        sqlitebrowser \
        foremost scalpel testdisk \
        sleuthkit autopsy
    
} > /dev/null 2>&1

# ============================================================================
# REVERSE ENGINEERING TOOLS - Taking shit apart since forever
# ============================================================================

log "Installing reverse engineering arsenal"

# Radare2 and Cutter (if not already installed)
if ! command -v r2 &> /dev/null; then
    log "Installing radare2 from git"
    git clone -q https://github.com/radareorg/radare2 /tmp/radare2
    cd /tmp/radare2 && ./sys/install.sh > /dev/null 2>&1
    cd && rm -rf /tmp/radare2
fi

# Ghidra - the big boy
log "Installing Ghidra"
{
    wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.2_build/ghidra_10.3.2_PUBLIC_20230711.zip -O /tmp/ghidra.zip
    unzip -q /tmp/ghidra.zip -d $REVERSE_ENG/tools/
    mv $REVERSE_ENG/tools/ghidra_* $REVERSE_ENG/tools/ghidra
    rm /tmp/ghidra.zip
    
    # Create Ghidra launcher
    cat > /usr/local/bin/ghidra << EOF
#!/bin/bash
cd $REVERSE_ENG/tools/ghidra && ./ghidraRun
EOF
    chmod +x /usr/local/bin/ghidra
} > /dev/null 2>&1

# Binary Ninja (demo version)
log "Setting up Binary Ninja"
{
    wget -q https://cdn.binary.ninja/installers/XVi8mAU8TK/BinaryNinja-demo.zip -O /tmp/binaryninja.zip
    unzip -q /tmp/binaryninja.zip -d $REVERSE_ENG/tools/
    mv $REVERSE_ENG/tools/binaryninja $REVERSE_ENG/tools/binary-ninja
    rm /tmp/binaryninja.zip
} > /dev/null 2>&1

# IDA Freeware (manual download reminder)
log "Note: IDA Freeware requires manual download from Hex-Rays website"
log "Would be installed in: $REVERSE_ENG/tools/ida"

# ============================================================================
# PYTHON REVERSE ENGINEERING LIBRARIES
# ============================================================================

log "Installing Python RE libraries"
{
    pip3 install -q \
        capstone unicorn keystone-engine \
        ropper r2pipe \
        pefile pydasm \
        angr claripy cle pyvex \
        z3-solver \
        lief \
        pwnlib \
        volatility3
    
    # Install pwntools separately because it's special
    pip3 install -q pwntools
    
} > /dev/null 2>&1

# ============================================================================
# DEVELOPMENT TOOLS & FRAMEWORKS
# ============================================================================

log "Setting up development environment"

# Node.js tools
log "Installing Node.js development tools"
{
    npm install -g -q \
        typescript \
        webpack \
        nodemon \
        eslint \
        prettier \
        yarn \
        create-react-app \
        vue-cli \
        @angular/cli
    
} > /dev/null 2>&1

# Go tools for development and analysis
log "Installing Go development tools"
{
    export GOPATH=$USER_HOME/go
    export PATH=$PATH:$GOPATH/bin

    go install github.com/golang/go@latest
    go install github.com/gorilla/mux@latest
    go install github.com/stretchr/testify@latest
    
    # RE-related Go tools
    go install github.com/radareorg/r2pm@latest
    go install github.com/sibears/IDAGolangHelper@latest
    
} > /dev/null 2>&1

# Rust tools
log "Setting up Rust development"
{
    cargo install -q \
        cargo-edit \
        cargo-watch \
        cargo-audit \
        bat \
        exa \
        fd-find \
        ripgrep
    
} > /dev/null 2>&1

# ============================================================================
# ANALYSIS TOOLS & SCRIPTS
# ============================================================================

log "Creating analysis tools and scripts"

# Binary analysis script
cat > $REVERSE_ENG/scripts/analyze_binary.sh << 'EOF'
#!/bin/bash
# Comprehensive binary analysis script

set -e

BINARY="$1"
OUTPUT_DIR="${2:-./analysis_$(basename "$BINARY")}"

[ -z "$BINARY" ] && { 
    echo "Usage: analyze_binary.sh <binary> [output_dir]"
    exit 1 
}

[ -f "$BINARY" ] || {
    echo "Error: Binary file not found: $BINARY"
    exit 1
}

mkdir -p "$OUTPUT_DIR"

echo "Starting comprehensive analysis of: $BINARY"
echo "Output directory: $OUTPUT_DIR"

# Basic file info
echo "=== FILE INFORMATION ===" > "$OUTPUT_DIR/analysis.txt"
file "$BINARY" >> "$OUTPUT_DIR/analysis.txt"
echo "" >> "$OUTPUT_DIR/analysis.txt"

# Strings analysis
echo "=== STRINGS ANALYSIS ===" >> "$OUTPUT_DIR/analysis.txt"
strings "$BINARY" > "$OUTPUT_DIR/strings.txt"
echo "Strings found: $(wc -l < "$OUTPUT_DIR/strings.txt")" >> "$OUTPUT_DIR/analysis.txt"
echo "" >> "$OUTPUT_DIR/analysis.txt"

# Binary details
echo "=== BINARY DETAILS ===" >> "$OUTPUT_DIR/analysis.txt"
readelf -h "$BINARY" > "$OUTPUT_DIR/elf_header.txt" 2>/dev/null || true
objdump -x "$BINARY" > "$OUTPUT_DIR/objdump.txt" 2>/dev/null || true

# PE analysis if applicable
if command -v pefile &> /dev/null && [[ "$BINARY" =~ \.(exe|dll)$ ]]; then
    echo "=== PE ANALYSIS ===" >> "$OUTPUT_DIR/analysis.txt"
    python3 -c "
import pefile
import sys
pe = pefile.PE('$BINARY')
print('PE Sections:')
for section in pe.sections:
    print(f'  {section.Name.decode().strip():12} {section.Misc_VirtualSize:8x} {section.SizeOfRawData:8x}')
print(f'\nImports:')
for entry in pe.DIRECTORY_ENTRY_IMPORT:
    print(f'  {entry.dll.decode()}')
    for imp in entry.imports:
        if imp.name:
            print(f'    {imp.name.decode()}')
" > "$OUTPUT_DIR/pe_analysis.txt" 2>/dev/null || true
fi

# Radare2 analysis
echo "=== RADARE2 ANALYSIS ===" >> "$OUTPUT_DIR/analysis.txt"
r2 -qc "aaa; iS; il" "$BINARY" > "$OUTPUT_DIR/radare2_info.txt" 2>/dev/null || true

echo "Analysis complete: $OUTPUT_DIR"
EOF

chmod +x $REVERSE_ENG/scripts/analyze_binary.sh

# Malware analysis script
cat > $REVERSE_ENG/scripts/malware_analysis.sh << 'EOF'
#!/bin/bash
# Malware analysis in isolated environment

set -e

SAMPLE="$1"
OUTPUT_DIR="${2:-./malware_analysis}"

[ -z "$SAMPLE" ] && { 
    echo "Usage: malware_analysis.sh <sample> [output_dir]"
    echo "WARNING: Use in isolated environment only!"
    exit 1 
}

mkdir -p "$OUTPUT_DIR"

echo "=== MALWARE ANALYSIS STARTED ==="
echo "Sample: $SAMPLE"
echo "Output: $OUTPUT_DIR"
echo "Timestamp: $(date)"
echo ""

# Create analysis report
{
    echo "Malware Analysis Report"
    echo "======================"
    echo "File: $SAMPLE"
    echo "Analyzed: $(date)"
    echo "Analyst: $USER"
    echo ""
    
    # Basic file info
    echo "1. BASIC FILE INFORMATION"
    echo "-----------------------"
    file "$SAMPLE"
    ls -la "$SAMPLE"
    echo ""
    
    # Cryptographic hashes
    echo "2. CRYPTOGRAPHIC HASHES"
    echo "----------------------"
    echo "MD5:    $(md5sum "$SAMPLE" | cut -d' ' -f1)"
    echo "SHA1:   $(sha1sum "$SAMPLE" | cut -d' ' -f1)"
    echo "SHA256: $(sha256sum "$SAMPLE" | cut -d' ' -f1)"
    echo ""
    
    # Strings with context
    echo "3. INTERESTING STRINGS"
    echo "---------------------"
    strings "$SAMPLE" | grep -E "(http|https|ftp|www\.|cmd|powershell|reg|HKEY_|CreateRemoteThread|VirtualAlloc)" | head -20
    echo ""
    
    # PE information if applicable
    if [[ "$SAMPLE" =~ \.(exe|dll|scr)$ ]]; then
        echo "4. PE FILE ANALYSIS"
        echo "------------------"
        if command -v pefile &> /dev/null; then
            python3 -c "
import pefile
pe = pefile.PE('$SAMPLE')
print('Compile Time:', pe.FILE_HEADER.TimeDateStamp)
print('Entry Point:', pe.OPTIONAL_HEADER.AddressOfEntryPoint)
print('Image Base:', hex(pe.OPTIONAL_HEADER.ImageBase))
print('\nSections:')
for section in pe.sections:
    print(f'  {section.Name.decode().strip():12} {hex(section.VirtualAddress)} {section.Misc_VirtualSize}')
" 2>/dev/null || echo "PE analysis failed"
        fi
        echo ""
    fi
    
    # Network indicators
    echo "5. NETWORK INDICATORS"
    echo "-------------------"
    strings "$SAMPLE" | grep -E "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -10
    echo ""
    
} > "$OUTPUT_DIR/analysis_report.txt"

echo "Analysis complete: $OUTPUT_DIR/analysis_report.txt"
echo "WARNING: Handle sample with care in isolated environment!"
EOF

chmod +x $REVERSE_ENG/scripts/malware_analysis.sh

# Development build script
cat > $DEV_TOOLS/scripts/build_project.sh << 'EOF'
#!/bin/bash
# Universal project build script

set -e

PROJECT_DIR="${1:-.}"
BUILD_DIR="${2:-./build}"
BUILD_TYPE="${3:-Release}"

echo "Building project: $PROJECT_DIR"
echo "Build directory: $BUILD_DIR"
echo "Build type: $BUILD_TYPE"

mkdir -p "$BUILD_DIR"
cd "$BUILD_DIR"

# Detect project type and build accordingly
if [ -f "$PROJECT_DIR/CMakeLists.txt" ]; then
    echo "CMake project detected"
    cmake -DCMAKE_BUILD_TYPE=$BUILD_TYPE "$PROJECT_DIR"
    make -j$(nproc)
    
elif [ -f "$PROJECT_DIR/package.json" ]; then
    echo "Node.js project detected"
    cd "$PROJECT_DIR"
    npm install
    npm run build
    
elif [ -f "$PROJECT_DIR/Cargo.toml" ]; then
    echo "Rust project detected"
    cd "$PROJECT_DIR"
    cargo build --release
    
elif [ -f "$PROJECT_DIR/go.mod" ]; then
    echo "Go project detected"
    cd "$PROJECT_DIR"
    go build -o "$BUILD_DIR" ./...
    
elif [ -f "$PROJECT_DIR/setup.py" ]; then
    echo "Python project detected"
    cd "$PROJECT_DIR"
    pip3 install -e .
    
else
    echo "Unknown project type or no build system detected"
    echo "Available build files:"
    ls -la "$PROJECT_DIR" | grep -E "(CMakeLists.txt|package.json|Cargo.toml|go.mod|setup.py|Makefile)" || true
fi

echo "Build completed"
EOF

chmod +x $DEV_TOOLS/scripts/build_project.sh

# ============================================================================
# PYTHON ANALYSIS SCRIPTS
# ============================================================================

log "Creating Python analysis scripts"

# Python binary analysis helper
cat > $REVERSE_ENG/scripts/binary_analysis.py << 'EOF'
#!/usr/bin/env python3
"""
Advanced Binary Analysis Toolkit
Comprehensive binary analysis using multiple tools
"""

import os
import sys
import subprocess
import hashlib
import pefile
import lief
from pathlib import Path

class BinaryAnalyzer:
    def __init__(self, binary_path):
        self.binary_path = binary_path
        self.results = {}
        
    def calculate_hashes(self):
        """Calculate cryptographic hashes"""
        hashes = {}
        with open(self.binary_path, 'rb') as f:
            data = f.read()
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        return hashes
    
    def analyze_pe(self):
        """Analyze PE files"""
        try:
            pe = pefile.PE(self.binary_path)
            info = {
                'entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'image_base': pe.OPTIONAL_HEADER.ImageBase,
                'compile_time': pe.FILE_HEADER.TimeDateStamp,
                'sections': []
            }
            
            for section in pe.sections:
                info['sections'].append({
                    'name': section.Name.decode().rstrip('\x00'),
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData
                })
                
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_elf(self):
        """Analyze ELF files"""
        try:
            binary = lief.parse(self.binary_path)
            info = {
                'entry_point': binary.entrypoint,
                'sections': [],
                'imports': []
            }
            
            for section in binary.sections:
                info['sections'].append({
                    'name': section.name,
                    'virtual_address': section.virtual_address,
                    'size': section.size
                })
                
            return info
        except Exception as e:
            return {'error': str(e)}
    
    def run_analysis(self):
        """Run comprehensive analysis"""
        print(f"Analyzing: {self.binary_path}")
        
        # Basic file info
        file_info = subprocess.run(['file', self.binary_path], capture_output=True, text=True)
        self.results['file_info'] = file_info.stdout.strip()
        
        # Hashes
        self.results['hashes'] = self.calculate_hashes()
        
        # Architecture-specific analysis
        if self.binary_path.endswith(('.exe', '.dll')):
            self.results['pe_analysis'] = self.analyze_pe()
        elif self.binary_path.endswith(('.elf', '.so', '.o')) or 'ELF' in file_info.stdout:
            self.results['elf_analysis'] = self.analyze_elf()
        
        return self.results

def main():
    if len(sys.argv) != 2:
        print("Usage: binary_analysis.py <binary_file>")
        sys.exit(1)
    
    analyzer = BinaryAnalyzer(sys.argv[1])
    results = analyzer.run_analysis()
    
    print("\n=== ANALYSIS RESULTS ===")
    print(f"File Info: {results.get('file_info', 'N/A')}")
    print(f"SHA256: {results['hashes']['sha256']}")
    
    if 'pe_analysis' in results:
        print("\nPE Analysis:")
        print(f"Entry Point: 0x{results['pe_analysis'].get('entry_point', 0):x}")
        
    if 'elf_analysis' in results:
        print("\nELF Analysis:")
        print(f"Entry Point: 0x{results['elf_analysis'].get('entry_point', 0):x}")

if __name__ == "__main__":
    main()
EOF

chmod +x $REVERSE_ENG/scripts/binary_analysis.py

# ============================================================================
# ENVIRONMENT CONFIGURATION
# ============================================================================

log "Configuring development environment"

# Bashrc additions for RE and development
cat >> $USER_HOME/.bashrc << 'EOF'

# Reverse Engineering & Development Environment
export DEV_ROOT="$HOME/dev_ops"
export REVERSE_ENG="$DEV_ROOT/reverse_engineering"
export DEV_TOOLS="$DEV_ROOT/development"
export ANALYSIS_WORKSPACE="$DEV_ROOT/analysis"

export PATH="$PATH:$DEV_TOOLS/scripts:$REVERSE_ENG/scripts"
export PYTHONPATH="$PYTHONPATH:$REVERSE_ENG/scripts"

# Aliases for common tasks
alias analyze-bin="$REVERSE_ENG/scripts/analyze_binary.sh"
alias analyze-malware="$REVERSE_ENG/scripts/malware_analysis.sh"
alias build-project="$DEV_TOOLS/scripts/build_project.sh"
alias py-analyze="$REVERSE_ENG/scripts/binary_analysis.py"

alias ghidra="cd $REVERSE_ENG/tools/ghidra && ./ghidraRun"
alias radare2="r2"
alias cutter="cutter"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║        REVERSE ENGINEERING & DEVELOPMENT         ║"
echo "║                   WORKSHOP                       ║
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Available Commands:"
echo "  analyze-bin <binary>        - Comprehensive binary analysis"
echo "  analyze-malware <sample>    - Malware analysis (USE WITH CARE)"
echo "  build-project [dir]         - Universal project builder"
echo "  py-analyze <binary>         - Python binary analysis"
echo ""
echo "  ghidra                      - Launch Ghidra"
echo "  radare2                     - Launch radare2"
echo "  cutter                      - Launch Cutter GUI"
echo ""
echo "Workspace: $DEV_ROOT"
echo "Tools: $REVERSE_ENG/tools"
echo ""
EOF

# Set proper permissions
chown -R $SUDO_USER:$SUDO_USER $DEV_ROOT
chown -R $SUDO_USER:$SUDO_USER $USER_HOME/go

# ============================================================================
# COMPLETION & USAGE
# ============================================================================

log "Reverse Engineering & Development Platform complete"
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║                 QUICK START GUIDE                ║"
echo "║                                                  ║"
echo "║  1. analyze-bin /path/to/binary                  ║"
echo "║  2. analyze-malware /path/to/sample              ║
echo "║  3. build-project /path/to/project               ║"
echo "║  4. ghidra (for GUI reverse engineering)         ║"
echo "║                                                  ║"
echo "║  Tools Installed:                                ║"
echo "║    • Ghidra, radare2, Cutter, Binary Ninja       ║"
echo "║    • IDA Freeware (manual install)               ║"
echo "║    • Python RE stack (angr, capstone, etc.)      ║
echo "║    • Full development toolchain                  ║"
echo "║    • Analysis scripts and utilities              ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Workspace: $DEV_ROOT"
echo "Reverse Engineering: $REVERSE_ENG"
echo "Development Tools: $DEV_TOOLS"
echo ""
echo "Log out and back in for environment changes to take effect."
echo ""
echo "WARNING: Malware analysis should only be performed in isolated environments!"
