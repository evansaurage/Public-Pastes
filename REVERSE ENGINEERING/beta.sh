#!/bin/bash

# AUTOMATION-FOCUSED REVERSE ENGINEERING & DEVELOPMENT PLATFORM
# Only tools that can be scripted, automated, and run headless
# No GUI tools, no manual processes, just pure automation power

set -e

# Configuration
USER_HOME="/home/$SUDO_USER"
AUTO_ROOT="$USER_HOME/auto_re"
SCRIPTS_DIR="$AUTO_ROOT/scripts"
TOOLS_DIR="$AUTO_ROOT/tools"
WORKSPACES="$AUTO_ROOT/workspaces"
OUTPUT_DIR="$AUTO_ROOT/output"

# Directories for specific automation types
mkdir -p {$SCRIPTS_DIR,$TOOLS_DIR,$WORKSPACES,$OUTPUT_DIR}
mkdir -p $WORKSPACES/{binaries,malware,projects,reports}
mkdir -p $SCRIPTS_DIR/{analysis,extraction,monitoring,reporting}

log() { echo "[+] $1"; }

# ============================================================================
# CORE AUTOMATION DEPENDENCIES
# ============================================================================

log "Installing automation dependencies"
{
    apt update -qq
    apt upgrade -y -qq
    
    # Core automation stack
    apt install -y -qq \
        python3 python3-pip python3-venv python3-dev \
        build-essential cmake ninja-build \
        git curl wget jq xmlstarlet sqlite3 csvkit \
        parallel expect automake autoconf libtool \
        pkg-config libssl-dev libffi-dev \
        golang-go rustc cargo \
        nodejs npm
    
    # Analysis tools that work headless
    apt install -y -qq \
        binutils binwalk foremost strings \
        file hexedit hexcurse \
        radare2 yara lynis chkrootkit \
        tcpdump tshark nmap masscan \
        exiftool exiv2 steghide outguess \
        sleuthkit foremost testdisk
    
} > /dev/null 2>&1

# ============================================================================
# PYTHON AUTOMATION STACK
# ============================================================================

log "Installing Python automation libraries"
{
    pip3 install -q \
        # Binary analysis
        capstone unicorn keystone-engine \
        pefile pydasm lief \
        angr claripy cle pyvex \
        z3-solver \
        # Web and automation
        requests beautifulsoup4 selenium scrapy \
        playwright pyautogui \
        # Data processing
        pandas numpy matplotlib seaborn \
        scikit-learn jupyter ipython \
        # RE and security
        pwntools ropper r2pipe \
        volatility3 yara-python \
        # Utilities
        click typer rich progress \
        python-magic python-dateutil
    
    # Install playwright browsers headless
    python3 -m playwright install --with-deps
    
} > /dev/null 2>&1

# ============================================================================
# GO AUTOMATION TOOLS
# ============================================================================

log "Installing Go automation tools"
{
    export GOPATH=$USER_HOME/go
    export PATH=$PATH:$GOPATH/bin

    # Project Discovery suite (automation-focused)
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/projectdiscovery/notify/cmd/notify@latest
    
    # File and content analysis
    go install -v github.com/tomnomnom/assetfinder@latest
    go install -v github.com/tomnomnom/waybackurls@latest
    go install -v github.com/tomnomnom/unfurl@latest
    go install -v github.com/ffuf/ffuf@latest
    go install -v github.com/hakluke/hakrawler@latest
    
    # Binary analysis
    go install -v github.com/radareorg/r2pm@latest
    
} > /dev/null 2>&1

# ============================================================================
# HEADLESS RE TOOLS
# ============================================================================

log "Installing headless reverse engineering tools"

# Radare2 for scripting
if ! command -v r2 &> /dev/null; then
    log "Installing radare2 for headless analysis"
    git clone -q https://github.com/radareorg/radare2 /tmp/radare2
    cd /tmp/radare2 && ./sys/install.sh > /dev/null 2>&1
    cd && rm -rf /tmp/radare2
fi

# Yara rules and compilation
log "Setting up Yara for automated detection"
{
    git clone -q https://github.com/Yara-Rules/rules.git $TOOLS_DIR/yara-rules
    # Compile all rules for faster scanning
    find $TOOLS_DIR/yara-rules -name "*.yar" -exec cat {} \; > $TOOLS_DIR/compiled_rules.yar 2>/dev/null || true
    
} > /dev/null 2>&1

# ============================================================================
# AUTOMATION SCRIPTS - THE CORE
# ============================================================================

log "Creating automation scripts"

# Automated binary analysis pipeline
cat > $SCRIPTS_DIR/analysis/binary_pipeline.py << 'EOF'
#!/usr/bin/env python3
"""
Automated Binary Analysis Pipeline
Input: Binary file -> Output: Comprehensive analysis report
"""

import argparse
import json
import hashlib
import subprocess
import sys
from pathlib import Path
import lief
import pefile
import yara
from datetime import datetime

class BinaryAnalysisPipeline:
    def __init__(self, binary_path, output_dir):
        self.binary_path = Path(binary_path)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = {
            'metadata': {},
            'analysis': {},
            'indicators': []
        }
    
    def calculate_hashes(self):
        """Calculate file hashes"""
        with open(self.binary_path, 'rb') as f:
            data = f.read()
            return {
                'md5': hashlib.md5(data).hexdigest(),
                'sha1': hashlib.sha1(data).hexdigest(),
                'sha256': hashlib.sha256(data).hexdigest()
            }
    
    def run_strings_analysis(self):
        """Extract and analyze strings"""
        try:
            result = subprocess.run(['strings', self.binary_path], 
                                  capture_output=True, text=True)
            strings_output = result.stdout.split('\n')
            
            # Look for interesting strings
            interesting = []
            patterns = [
                'http://', 'https://', 'ftp://',
                'cmd.exe', 'powershell', 'bash',
                'CreateRemoteThread', 'VirtualAlloc',
                'reg add', 'HKEY_',
                '.dll', '.exe', '.sys'
            ]
            
            for string in strings_output:
                if any(pattern in string.lower() for pattern in patterns):
                    interesting.append(string.strip())
            
            return {
                'total_strings': len(strings_output),
                'interesting_strings': interesting[:100]  # Limit output
            }
        except Exception as e:
            return {'error': str(e)}
    
    def run_yara_scan(self):
        """Scan binary with Yara rules"""
        try:
            # Compile rules
            rules = yara.compile(filepath=f'{Path.home()}/auto_re/tools/compiled_rules.yar')
            matches = rules.match(str(self.binary_path))
            
            return [{
                'rule': match.rule,
                'tags': match.tags,
                'meta': match.meta
            } for match in matches]
        except Exception as e:
            return {'error': str(e)}
    
    def analyze_with_radare2(self):
        """Run radare2 analysis commands"""
        try:
            commands = [
                'aaa',  # Auto analysis
                'iS',   # Sections
                'il',   # Libraries
                'iI',   # Imports
                'iz'    # Strings in data sections
            ]
            
            results = {}
            for cmd in commands:
                result = subprocess.run(['r2', '-qc', cmd, self.binary_path],
                                      capture_output=True, text=True)
                results[cmd] = result.stdout.strip()
            
            return results
        except Exception as e:
            return {'error': str(e)}
    
    def execute_pipeline(self):
        """Execute full analysis pipeline"""
        print(f"Starting analysis pipeline for: {self.binary_path}")
        
        # Basic metadata
        self.results['metadata'] = {
            'filename': self.binary_path.name,
            'file_size': self.binary_path.stat().st_size,
            'analysis_time': datetime.now().isoformat(),
            'hashes': self.calculate_hashes()
        }
        
        # Run analysis steps
        self.results['analysis']['strings'] = self.run_strings_analysis()
        self.results['analysis']['yara'] = self.run_yara_scan()
        self.results['analysis']['radare2'] = self.analyze_with_radare2()
        
        # Save results
        report_file = self.output_dir / f"{self.binary_path.name}_analysis.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Analysis complete: {report_file}")
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Automated Binary Analysis Pipeline')
    parser.add_argument('binary', help='Path to binary file')
    parser.add_argument('-o', '--output', default='./analysis_output', 
                       help='Output directory')
    
    args = parser.parse_args()
    
    pipeline = BinaryAnalysisPipeline(args.binary, args.output)
    results = pipeline.execute_pipeline()
    
    # Print summary
    print("\n=== ANALYSIS SUMMARY ===")
    print(f"File: {results['metadata']['filename']}")
    print(f"SHA256: {results['metadata']['hashes']['sha256']}")
    print(f"Interesting strings: {len(results['analysis']['strings'].get('interesting_strings', []))}")
    print(f"Yara matches: {len(results['analysis']['yara'])}")

if __name__ == "__main__":
    main()
EOF

# Automated network reconnaissance
cat > $SCRIPTS_DIR/analysis/network_recon.py << 'EOF'
#!/usr/bin/env python3
"""
Automated Network Reconnaissance Pipeline
"""

import subprocess
import json
import csv
from datetime import datetime
import argparse
from pathlib import Path

class NetworkRecon:
    def __init__(self, target, output_dir):
        self.target = target
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.results = {}
    
    def run_nmap_scan(self):
        """Run comprehensive nmap scan"""
        print("Running Nmap scan...")
        output_file = self.output_dir / "nmap_scan.xml"
        
        cmd = [
            'nmap', '-sS', '-A', '-T4', '-p-',
            '-oX', str(output_file),
            self.target
        ]
        
        subprocess.run(cmd, capture_output=True)
        return str(output_file)
    
    def run_subdomain_enum(self):
        """Enumerate subdomains"""
        print("Enumerating subdomains...")
        output_file = self.output_dir / "subdomains.txt"
        
        try:
            # Try multiple tools
            tools = ['subfinder', 'assetfinder']
            all_subdomains = set()
            
            for tool in tools:
                try:
                    if tool == 'subfinder':
                        result = subprocess.run([tool, '-d', self.target, '-silent'],
                                              capture_output=True, text=True)
                    elif tool == 'assetfinder':
                        result = subprocess.run([tool, self.target],
                                              capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        subdomains = result.stdout.strip().split('\n')
                        all_subdomains.update(subdomains)
                except:
                    continue
            
            # Save results
            with open(output_file, 'w') as f:
                f.write('\n'.join(sorted(all_subdomains)))
            
            return list(all_subdomains)
        except Exception as e:
            print(f"Subdomain enum failed: {e}")
            return []
    
    def run_web_discovery(self, subdomains):
        """Discover web content"""
        print("Discovering web content...")
        
        if not subdomains:
            return {}
        
        # Use first 10 subdomains for demonstration
        targets = subdomains[:10]
        results = {}
        
        for target in targets:
            try:
                # HTTPx for basic info
                http_result = subprocess.run(['httpx', '-silent', '-title', '-status-code', '-tech-detect', target],
                                           capture_output=True, text=True)
                if http_result.returncode == 0:
                    results[target] = http_result.stdout.strip()
            except:
                continue
        
        return results
    
    def execute_recon(self):
        """Execute full reconnaissance pipeline"""
        print(f"Starting network reconnaissance for: {self.target}")
        
        # Run reconnaissance steps
        nmap_results = self.run_nmap_scan()
        subdomains = self.run_subdomain_enum()
        web_discovery = self.run_web_discovery(subdomains)
        
        # Compile results
        self.results = {
            'target': self.target,
            'timestamp': datetime.now().isoformat(),
            'nmap_scan': nmap_results,
            'subdomains_found': len(subdomains),
            'subdomains': subdomains,
            'web_discovery': web_discovery
        }
        
        # Save comprehensive report
        report_file = self.output_dir / "recon_report.json"
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"Reconnaissance complete: {report_file}")
        return self.results

def main():
    parser = argparse.ArgumentParser(description='Automated Network Reconnaissance')
    parser.add_argument('target', help='Target domain or IP')
    parser.add_argument('-o', '--output', default='./recon_output',
                       help='Output directory')
    
    args = parser.parse_args()
    
    recon = NetworkRecon(args.target, args.output)
    results = recon.execute_recon()
    
    # Print summary
    print("\n=== RECON SUMMARY ===")
    print(f"Target: {results['target']}")
    print(f"Subdomains found: {results['subdomains_found']}")
    print(f"Web services discovered: {len(results['web_discovery'])}")

if __name__ == "__main__":
    main()
EOF

# Automated monitoring script
cat > $SCRIPTS_DIR/monitoring/auto_monitor.py << 'EOF'
#!/usr/bin/env python3
"""
Automated System and Network Monitoring
"""

import time
import json
import subprocess
import psutil
from datetime import datetime
from pathlib import Path

class AutoMonitor:
    def __init__(self, output_dir, interval=60):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.interval = interval
        self.running = False
        
    def collect_system_metrics(self):
        """Collect system performance metrics"""
        return {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': psutil.cpu_percent(interval=1),
            'memory_percent': psutil.virtual_memory().percent,
            'disk_usage': psutil.disk_usage('/').percent,
            'network_io': psutil.net_io_counters()._asdict(),
            'active_connections': len(psutil.net_connections())
        }
    
    def capture_network_traffic(self, duration=10):
        """Capture network traffic for analysis"""
        pcap_file = self.output_dir / f"capture_{int(time.time())}.pcap"
        
        try:
            subprocess.run([
                'timeout', str(duration),
                'tcpdump', '-i', 'any', '-w', str(pcap_file), '-c', '1000'
            ], capture_output=True)
            return str(pcap_file)
        except:
            return None
    
    def check_suspicious_activity(self):
        """Check for suspicious system activity"""
        suspicious = []
        
        # Check for unusual processes
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                info = proc.info
                # Simple heuristic: high CPU with unknown process
                if info['cpu_percent'] > 50 and 'unknown' in info['name'].lower():
                    suspicious.append(info)
            except:
                pass
        
        return suspicious
    
    def run_monitoring_cycle(self):
        """Run one monitoring cycle"""
        cycle_data = {
            'system_metrics': self.collect_system_metrics(),
            'network_capture': self.capture_network_traffic(5),
            'suspicious_activity': self.check_suspicious_activity()
        }
        
        # Save cycle data
        cycle_file = self.output_dir / f"cycle_{int(time.time())}.json"
        with open(cycle_file, 'w') as f:
            json.dump(cycle_data, f, indent=2)
        
        return cycle_data
    
    def start_monitoring(self, duration=3600):
        """Start automated monitoring"""
        self.running = True
        start_time = time.time()
        
        print(f"Starting automated monitoring for {duration} seconds...")
        
        while self.running and (time.time() - start_time) < duration:
            try:
                cycle_data = self.run_monitoring_cycle()
                print(f"Cycle completed: {cycle_data['system_metrics']['timestamp']}")
                
                # Alert on suspicious activity
                if cycle_data['suspicious_activity']:
                    print(f"ALERT: Suspicious activity detected: {cycle_data['suspicious_activity']}")
                
                time.sleep(self.interval)
                
            except KeyboardInterrupt:
                print("Monitoring stopped by user")
                break
            except Exception as e:
                print(f"Monitoring error: {e}")
                time.sleep(self.interval)
        
        print("Monitoring completed")

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Automated System Monitoring')
    parser.add_argument('-o', '--output', default='./monitoring_output',
                       help='Output directory')
    parser.add_argument('-d', '--duration', type=int, default=3600,
                       help='Monitoring duration in seconds')
    parser.add_argument('-i', '--interval', type=int, default=60,
                       help='Monitoring interval in seconds')
    
    args = parser.parse_args()
    
    monitor = AutoMonitor(args.output, args.interval)
    monitor.start_monitoring(args.duration)

if __name__ == "__main__":
    main()
EOF

# Make scripts executable
chmod +x $SCRIPTS_DIR/analysis/*.py
chmod +x $SCRIPTS_DIR/monitoring/*.py

# ============================================================================
# AUTOMATION WORKFLOWS
# ============================================================================

# Batch processing script for multiple binaries
cat > $SCRIPTS_DIR/analysis/batch_processor.sh << 'EOF'
#!/bin/bash
# Batch processor for multiple binaries

set -e

INPUT_DIR="$1"
OUTPUT_DIR="${2:-./batch_analysis}"

[ -z "$INPUT_DIR" ] && {
    echo "Usage: batch_processor.sh <input_dir> [output_dir]"
    exit 1
}

mkdir -p "$OUTPUT_DIR"

echo "Starting batch processing of binaries in: $INPUT_DIR"

# Process all executable files
find "$INPUT_DIR" -type f -executable | while read binary; do
    if [ -f "$binary" ]; then
        filename=$(basename "$binary")
        echo "Processing: $filename"
        
        # Run analysis pipeline
        python3 $SCRIPTS_DIR/analysis/binary_pipeline.py "$binary" "$OUTPUT_DIR/$filename" || continue
        
        # Generate summary
        echo "Completed: $filename" >> "$OUTPUT_DIR/processing_log.txt"
    fi
done

echo "Batch processing complete: $OUTPUT_DIR"
echo "Processed files: $(find "$INPUT_DIR" -type f -executable | wc -l)"
EOF

chmod +x $SCRIPTS_DIR/analysis/batch_processor.sh

# Continuous monitoring service script
cat > $SCRIPTS_DIR/monitoring/start_monitoring_service.sh << 'EOF'
#!/bin/bash
# Start continuous monitoring as a service

set -e

OUTPUT_DIR="${1:-./continuous_monitoring}"
DURATION="${2:-86400}"  # 24 hours default

echo "Starting continuous monitoring service"
echo "Output: $OUTPUT_DIR"
echo "Duration: $DURATION seconds"

# Start monitoring in background
python3 $SCRIPTS_DIR/monitoring/auto_monitor.py \
    --output "$OUTPUT_DIR" \
    --duration "$DURATION" \
    --interval 300 &
    
MONITOR_PID=$!

echo "Monitoring service started with PID: $MONITOR_PID"
echo "Stop with: kill $MONITOR_PID"
echo "Logs in: $OUTPUT_DIR"

# Save PID for management
echo $MONITOR_PID > "$OUTPUT_DIR/monitor.pid"
EOF

chmod +x $SCRIPTS_DIR/monitoring/start_monitoring_service.sh

# ============================================================================
# ENVIRONMENT SETUP
# ============================================================================

log "Setting up automation environment"

cat >> $USER_HOME/.bashrc << 'EOF'

# Automation-Focused Reverse Engineering Environment
export AUTO_RE="$HOME/auto_re"
export SCRIPTS_DIR="$AUTO_RE/scripts"
export TOOLS_DIR="$AUTO_RE/tools"
export WORKSPACES="$AUTO_RE/workspaces"

export PATH="$PATH:$SCRIPTS_DIR/analysis:$SCRIPTS_DIR/monitoring:$SCRIPTS_DIR/extraction:$SCRIPTS_DIR/reporting"

# Aliases for automation workflows
alias analyze-binary="python3 $SCRIPTS_DIR/analysis/binary_pipeline.py"
alias network-recon="python3 $SCRIPTS_DIR/analysis/network_recon.py"
alias start-monitor="$SCRIPTS_DIR/monitoring/start_monitoring_service.sh"
alias batch-process="$SCRIPTS_DIR/analysis/batch_processor.sh"

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║           AUTOMATION RE PLATFORM READY           ║"
echo "║        Headless, Scriptable, Production         ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Available Automation Pipelines:"
echo "  analyze-binary <file>            - Automated binary analysis"
echo "  network-recon <target>           - Automated reconnaissance"
echo "  start-monitor [dir]              - Continuous monitoring"
echo "  batch-process <dir>              - Batch binary processing"
echo ""
echo "Workspace: $AUTO_RE"
echo "Scripts: $SCRIPTS_DIR"
echo ""
EOF

# Set permissions
chown -R $SUDO_USER:$SUDO_USER $AUTO_ROOT
chown -R $SUDO_USER:$SUDO_USER $USER_HOME/go

# ============================================================================
# DEPLOYMENT COMPLETE
# ============================================================================

log "Automation-Focused RE Platform deployment complete"
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║                 AUTOMATION READY                 ║"
echo "║                                                  ║"
echo "║  Features:                                       ║"
echo "║    • Headless binary analysis pipeline           ║"
echo "║    • Automated network reconnaissance           ║"
echo "║    • Continuous system monitoring               ║"
echo "║    • Batch processing capabilities              ║"
echo "║    • Production-ready scripting environment     ║"
echo "║                                                  ║"
echo "║  No GUI tools, no manual processes              ║"
echo "║  Pure automation from input to output           ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Quick Start:"
echo "  1. analyze-binary /path/to/binary"
echo "  2. network-recon target.com"
echo "  3. start-monitor /monitoring/output"
echo "  4. batch-process /binaries/directory"
echo ""
echo "All tools are headless and designed for automation pipelines."
