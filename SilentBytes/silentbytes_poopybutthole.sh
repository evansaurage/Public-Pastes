#!/bin/bash

# silentbytes_poopybutthole.sh
# The digital equivalent of a rusty knife - ugly but gets the job done
# Written with the elegance of a drunken sailor and the precision of a sledgehammer

set -e

# Who the fuck needs variables? Fuck it, we're using them anyway
USER_HOME="/home/$SUDO_USER"
WORKSPACE="$USER_HOME/workspace"  # Where the magic (and regret) happens
TOOLS_DIR="$WORKSPACE/tools"      # Our digital toolbox of questionable decisions

# Colors? Fuck colors. This is a terminal, not a rainbow.
log() { echo "[√] $1"; }    # Checkmark because we're optimistic bastards
err() { echo "[X] $1"; }    # X marks the spot where we fucked up

# Root check - because we're not script kiddies (anymore)
[ "$EUID" -eq 0 ] || { err "Listen here you little shit, I need root. Get your shit together."; exit 1; }

# ============================================================================
# SETUP WORKSPACE - Because organized chaos is still organized
# ============================================================================

log "Building our digital meth lab"
mkdir -p $WORKSPACE/{cases,evidence,tmp,logs,shit_that_worked_once} 
mkdir -p $TOOLS_DIR
mkdir -p $WORKSPACE/config

# ============================================================================
# INSTALL ESSENTIALS - The digital equivalent of duct tape and WD-40
# ============================================================================

log "Installing the usual suspects"
{
    # Update the fucking system
    apt update -qq
    apt upgrade -y -qq
    
    # The A-team of packages
    apt install -y -qq \
        git curl wget vim tmux htop \
        python3 python3-pip python3-venv python3-dev \
        build-essential libssl-dev libffi-dev cmake \
        golang-go jq sqlite3 xmlstarlet \
        tor torsocks proxychains4 openvpn wireguard \
        wireshark tshark tcpdump tcpflow tcpreplay \
        nmap masscan netdiscover arp-scan \
        aircrack-ng kismet
    
} > /dev/null 2>&1 || { err "Package installation went tits up"; exit 1; }

# ============================================================================
# PYTHON TOOLS - Because sometimes you need to automate your bad decisions
# ============================================================================

log "Installing Python libs - because writing C is for masochists"
{
    # The holy trinity of "I don't want to write this myself"
    pip3 install -q \
        requests beautifulsoup4 selenium scrapy \
        pandas numpy matplotlib seaborn \
        scapy pyshark pydivert \
        twint newspaper3k \
        maxminddb-geolite2 ipwhois shodan
    
} > /dev/null 2>&1 || { err "Python shit blew up"; exit 1; }

# ============================================================================
# GO TOOLS - For when you need speed and don't care about memory safety
# ============================================================================

log "Compiling Go tools - go grab a coffee, this might take a minute"
{
    export GOPATH=$USER_HOME/go
    export PATH=$PATH:$GOPATH/bin

    # The A-team of Go tools
    go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install github.com/projectdiscovery/katana/cmd/katana@latest
    go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install github.com/projectdiscovery/notify/cmd/notify@latest
    go install github.com/ffuf/ffuf@latest
    go install github.com/tomnomnom/assetfinder@latest
    go install github.com/tomnomnom/waybackurls@latest
    go install github.com/tomnomnom/unfurl@latest
    
} > /dev/null 2>&1 || { err "Go compilation shit the bed"; exit 1; }

# ============================================================================
# GIT REPOS - Stealing other people's code like a proper digital pirate
# ============================================================================

log "Pirating GitHub repos - it's not stealing if it's open source"
{
    cd $TOOLS_DIR
    
    # OSINT tools - because stalking is a skill
    git clone -q https://github.com/sherlock-project/sherlock
    git clone -q https://github.com/laramies/theHarvester
    git clone -q https://github.com/smicallef/spiderfoot
    git clone -q https://github.com/soxoj/maigret
    git clone -q https://github.com/megadose/holehe
    
    # Network tools - for when you need to know who's fucking with your packets
    git clone -q https://github.com/blechschmidt/massdns
    git clone -q https://github.com/bettercap/bettercap
    
    # Install the shit that needs installing
    cd sherlock && pip3 install -q -r requirements.txt && cd ..
    cd theHarvester && pip3 install -q -r requirements.txt && cd ..
    cd spiderfoot && pip3 install -q -r requirements.txt && cd ..
    cd holehe && pip3 install -q -r requirements.txt && cd ..
    
    # Build the C stuff because we're masochists
    cd massdns && make > /dev/null 2>&1 && cp bin/massdns /usr/local/bin/ && cd ..
    cd bettercap && make build > /dev/null 2>&1 && make install > /dev/null 2>&1 && cd ..
    
} > /dev/null 2>&1 || { err "Git operations went sideways"; exit 1; }

# ============================================================================
# CONFIGURATION FILES - Because defaults are for pussies
# ============================================================================

log "Writing config files - this is where we fuck everything up"

# Proxychains - for when you want to be someone else
cat > /etc/proxychains.conf << 'EOF'
# Silent Byte's Proxychains Config
# Because sometimes you need to hide your digital ass

strict_chain
quiet_mode
proxy_dns
tcp_read_time_out 15000
tcp_connect_time_out 8000

[ProxyList]
socks5 127.0.0.1 9050
EOF

# Case template - organized like my love life: a fucking mess
cat > $WORKSPACE/config/case_template << 'EOF'
case_name=""
target=""
started="$(date)"
status="active"
notes="I have no idea what I'm doing"
EOF

# ============================================================================
# CORE SCRIPTS - The actual useful shit
# ============================================================================

log "Writing scripts - because manual labor is for peasants"

# The main recon script - our digital Swiss Army knife
cat > $TOOLS_DIR/recon.sh << 'EOF'
#!/bin/bash
# recon.sh - The digital equivalent of kicking the tires
# Usage: recon.sh <target> [output_dir]

set -e

TARGET="$1"
OUTPUT="${2:-./recon_$TARGET}"

[ -z "$TARGET" ] && { 
    echo "Usage: recon.sh <target> [output_dir]"
    echo "Example: recon.sh example.com"
    echo "Pro tip: Don't be a dumbass, use a target"
    exit 1 
}

mkdir -p "$OUTPUT"

echo "Starting recon on $TARGET - this might take a while, go get a beer"

# Subdomain enumeration - because surface area is everything
if command -v subfinder &> /dev/null; then
    echo "[-] Finding subdomains (subfinder)"
    subfinder -d "$TARGET" -silent > "$OUTPUT/subdomains.txt" 2>/dev/null || true
fi

# Asset discovery - more targets, more problems
if command -v assetfinder &> /dev/null; then
    echo "[-] Discovering assets (assetfinder)"
    assetfinder "$TARGET" >> "$OUTPUT/subdomains.txt" 2>/dev/null || true
fi

# Port scanning - knocking on digital doors
if command -v naabu &> /dev/null; then
    echo "[-] Scanning ports (naabu)"
    naabu -list "$OUTPUT/subdomains.txt" -silent > "$OUTPUT/ports.txt" 2>/dev/null || true
fi

# Wayback machine - internet archaeology
if command -v waybackurls &> /dev/null; then
    echo "[-] Checking wayback machine"
    cat "$OUTPUT/subdomains.txt" | waybackurls > "$OUTPUT/wayback_urls.txt" 2>/dev/null || true
fi

# Basic nmap because it's the OG
if command -v nmap &> /dev/null; then
    echo "[-] Running nmap scan"
    nmap -sS -T4 -A "$TARGET" -oN "$OUTPUT/nmap_scan.txt" > /dev/null 2>&1 || true
fi

echo "[+] Recon complete: $OUTPUT"
echo "[+] Subdomains found: $(wc -l < "$OUTPUT/subdomains.txt" 2>/dev/null || echo 0)"
echo "[+] Now go hack the planet or whatever"
EOF

# Network monitoring - because packets don't lie (but people do)
cat > $TOOLS_DIR/netwatch.sh << 'EOF'
#!/bin/bash
# netwatch.sh - The digital equivalent of a security camera
# Usage: netwatch.sh [interface] [duration]

INTERFACE="${1:-any}"
DURATION="${2:-300}"
OUTPUT="capture_$(date +%Y%m%d_%H%M%S).pcap"

echo "[+] Watching $INTERFACE for $DURATION seconds"
echo "[+] Output: $OUTPUT"
echo "[+] Press Ctrl+C if you get bored"

# Let's capture some packets, you creepy bastard
timeout $DURATION tcpdump -i "$INTERFACE" -w "$OUTPUT"

if [ -f "$OUTPUT" ]; then
    echo "[+] Capture complete: $OUTPUT"
    echo "[+] Packet count: $(tcpdump -r "$OUTPUT" 2>/dev/null | wc -l || echo 0)"
else
    echo "[-] Capture failed - did you pick a real interface, dumbass?"
fi
EOF

# OSINT script - because people overshare and we appreciate that
cat > $TOOLS_DIR/osint.sh << 'EOF'
#!/bin/bash
# osint.sh - Legally questionable information gathering
# Usage: osint.sh <username/domain> [output_dir]

TARGET="$1"
OUTPUT="${2:-./osint_$TARGET}"

[ -z "$TARGET" ] && { 
    echo "Usage: osint.sh <username/domain> [output_dir]"
    echo "Remember: With great power comes great responsibility, or some shit like that"
    exit 1 
}

mkdir -p "$OUTPUT"

echo "[+] Starting OSINT on $TARGET"
echo "[+] This might violate some terms of service, but fuck 'em"

# Username search - digital stalking made easy
if [ -d "$TOOLS_DIR/sherlock" ]; then
    echo "[-] Checking social media (sherlock)"
    python3 "$TOOLS_DIR/sherlock/sherlock/sherlock.py" "$TARGET" --no-color > "$OUTPUT/sherlock.txt" 2>/dev/null || true
fi

# Email check - because why not
if command -v holehe &> /dev/null; then
    echo "[-] Checking email accounts (holehe)"
    holehe "$TARGET" > "$OUTPUT/emails.txt" 2>/dev/null || true
fi

# Domain recon - theHarvester never gets old
if [ -d "$TOOLS_DIR/theHarvester" ]; then
    echo "[-] Harvesting domain info (theHarvester)"
    python3 "$TOOLS_DIR/theHarvester/theHarvester.py" -d "$TARGET" -b all > "$OUTPUT/theharvester.txt" 2>/dev/null || true
fi

# Maigret - because one OSINT tool isn't enough
if [ -d "$TOOLS_DIR/maigret" ]; then
    echo "[-] Advanced OSINT (maigret)"
    python3 "$TOOLS_DIR/maigret/maigret.py" "$TARGET" > "$OUTPUT/maigret.txt" 2>/dev/null || true
fi

echo "[+] OSINT complete: $OUTPUT"
echo "[+] Now you know more about $TARGET than their own mother"
EOF

# Case management - because we're professionals (kind of)
cat > $TOOLS_DIR/case.sh << 'EOF'
#!/bin/bash
# case.sh - Because even chaos needs organization
# Usage: case.sh {new|list|info} [case_name]

CMD="$1"
NAME="$2"

case "$CMD" in
    new)
        [ -z "$NAME" ] && { 
            echo "Usage: case.sh new <case_name>"
            echo "Pro tip: Don't use spaces, you'll regret it"
            exit 1 
        }
        
        CASE_DIR="$WORKSPACE/cases/$(echo "$NAME" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')"
        mkdir -p "$CASE_DIR"/{recon,evidence,notes,logs,screenshots}
        
        # Create case config because we're organized bastards
        sed "s/case_name=\"\"/case_name=\"$NAME\"/" "$WORKSPACE/config/case_template" > "$CASE_DIR/case.conf"
        echo "target=\"\"" >> "$CASE_DIR/case.conf"
        
        echo "[+] Case created: $CASE_DIR"
        echo "[+] Now go break some laws (just kidding, maybe)"
        ;;
        
    list)
        echo "[+] Active cases:"
        find "$WORKSPACE/cases" -name "case.conf" 2>/dev/null | while read conf; do
            name=$(grep 'case_name=' "$conf" | cut -d'"' -f2)
            target=$(grep 'target=' "$conf" | cut -d'"' -f2)
            echo "    $(dirname "$conf") | $name | $target"
        done || echo "    No cases found - get to work, lazy ass"
        ;;
        
    info)
        [ -z "$NAME" ] && { 
            echo "Usage: case.sh info <case_name>"
            exit 1 
        }
        
        CASE_DIR="$WORKSPACE/cases/$(echo "$NAME" | tr ' ' '_' | tr '[:upper:]' '[:lower:]')"
        if [ -f "$CASE_DIR/case.conf" ]; then
            echo "[+] Case info: $CASE_DIR"
            cat "$CASE_DIR/case.conf"
        else
            echo "[-] Case not found - did you spell it right, dumbass?"
        fi
        ;;
        
    *)
        echo "Usage: case.sh {new|list|info} [case_name]"
        echo "Available commands:"
        echo "  new <name>    - Create a new case"
        echo "  list          - List all cases" 
        echo "  info <name>   - Show case info"
        ;;
esac
EOF

# OPSEC script - covering our digital ass since whenever
cat > $TOOLS_DIR/opsec.sh << 'EOF'
#!/bin/bash
# opsec.sh - Because getting caught is for amateurs
# Usage: opsec.sh {tor|clear|vpn}

CMD="$1"

case "$CMD" in
    tor)
        echo "[+] Starting Tor service"
        systemctl start tor
        echo "[+] Tor enabled - you're now a ghost in the machine"
        ;;
        
    clear)
        echo "[+] Clearing digital footprints"
        echo "" > ~/.bash_history
        rm -rf /tmp/*
        history -c
        echo "[+] Basic cleanup complete - the feds will never know (probably)"
        ;;
        
    vpn)
        echo "[+] Don't be a dumbass, use a real VPN"
        echo "[+] I recommend Mullvad or ProtonVPN"
        echo "[+] This script can't hold your hand through everything"
        ;;
        
    *)
        echo "Usage: opsec.sh {tor|clear|vpn}"
        echo "Available commands:"
        echo "  tor    - Enable Tor routing"
        echo "  clear  - Clear basic traces"
        echo "  vpn    - Get VPN advice (because you need it)"
        ;;
esac
EOF

# Make everything executable because security is for pussies
chmod +x $TOOLS_DIR/*.sh

# ============================================================================
# ENVIRONMENT SETUP - Making life slightly less painful
# ============================================================================

log "Setting up environment - try not to fuck this up"

# Add our shit to bashrc because we're considerate like that
cat >> $USER_HOME/.bashrc << 'EOF'

# Silent Byte's Digital Playground
alias recon="$TOOLS_DIR/recon.sh"
alias netwatch="$TOOLS_DIR/netwatch.sh"
alias osint="$TOOLS_DIR/osint.sh" 
alias case="$TOOLS_DIR/case.sh"
alias opsec="$TOOLS_DIR/opsec.sh"

export WORKSPACE="$WORKSPACE"
export TOOLS_DIR="$TOOLS_DIR"
export PATH="$PATH:$TOOLS_DIR"

echo ""
echo "╔═══════════════════════════════════════╗"
echo "║        SILENT BYTE'S WORKSHOP         ║"
echo "║   Because fuck it, we'll do it live   ║"
echo "╚═══════════════════════════════════════╝"
echo ""
echo "Available commands:"
echo "  recon <target>     - Comprehensive reconnaissance"
echo "  osint <target>     - OSINT gathering"
echo "  netwatch <iface>   - Network monitoring"
echo "  case <cmd> <name>  - Case management"
echo "  opsec <cmd>        - Operational security"
echo ""
echo "Workspace: $WORKSPACE"
echo "Tools: $TOOLS_DIR"
echo ""
EOF

# Set permissions because we're not animals
chown -R $SUDO_USER:$SUDO_USER $WORKSPACE
chown -R $SUDO_USER:$SUDO_USER $USER_HOME/go

# ============================================================================
# WE'RE DONE - Go break something
# ============================================================================

log "Setup complete, you magnificent bastard"
echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║                  QUICK START                     ║"
echo "║                                                  ║"
echo "║  1. case new 'investigation_name'                ║"
echo "║  2. recon target.com                             ║"
echo "║  3. osint username                               ║"
echo "║  4. netwatch eth0                                ║"
echo "║  5. opsec tor                                    ║"
echo "║                                                  ║"
echo "║  Remember: With great power comes great          ║"
echo "║  responsibility to not be a complete dickhead    ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "Workspace: $WORKSPACE"
echo "Tools: $TOOLS_DIR"
echo ""
echo "Now log out and back in, you beautiful son of a bitch."
echo "Or don't. I'm a script, not your mother."
