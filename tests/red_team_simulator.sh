#!/bin/bash
# ALPHVDR Red Team Simulator
# This script safely simulates attacker behavior to trigger ALPHVDR's traps.

echo -e "\n🔥 ALPHVDR RED TEAM SIMULATOR 🔥"
echo "=================================="
echo "Note: The EDR must be running as root (sudo cargo run) in another terminal for this to work."
echo "Press ENTER to begin simulation..."
read

echo -e "\n[1] Simulating Cloud Credential Theft (AWS Honeytoken)..."
# Simulate an info-stealer trying to scrape AWS credentials
cat ~/.aws/credentials &>/dev/null
echo "Triggered! Check EDR logs for HONEYTOKEN_TRIGGERED."
sleep 1

echo -e "\n[2] Simulating Kubernetes Lateral Movement (K8s Honeytoken)..."
# Simulate a cloud-native worm looking for cluster access
cat ~/.kube/config &>/dev/null
echo "Triggered! Check EDR logs for HONEYTOKEN_TRIGGERED."
sleep 1

echo -e "\n[3] Simulating SSH Backdoor Persistence..."
# Simulate an attacker dropping an SSH key
echo "# redteam_test" >> ~/.ssh/authorized_keys 2>/dev/null
echo "Triggered! Check EDR logs for HONEYTOKEN_TRIGGERED."
sleep 1

echo -e "\n[4] Simulating Firmware Rootkit Installer..."
# Simulate a rootkit trying to flash the Intel ME or NVRAM
echo "test" > /dev/mei0 2>/dev/null
echo "Triggered! Check EDR logs for HARDWARE-LOCK."
sleep 1

echo -e "\n[5] Simulating Memory Scraper / Credential Dumper..."
# Find the PID of our dummy keepassxc ghost process
GHOST_PID=$(pgrep -f "/tmp/alphvdr_decoys/keepassxc")
if [ -n "$GHOST_PID" ]; then
    echo "Found Ghost Process (KeePassXC) at PID $GHOST_PID. Attempting to ptrace..."
    # Simply using strace triggers sys_enter_ptrace
    strace -p $GHOST_PID 2>/dev/null &
    sleep 1
    echo "Triggered! Check EDR logs for GHOST_PROCESS_TRAP."
else
    echo "Ghost process not found. Is ALPHVDR running?"
fi

echo -e "\n[6] Simulating Ransomware Outbreak (Triggering ZFS Rollback)..."
# Create rapid .enc files to trigger the heuristic
echo "Generating fake ransomware payload..."
mkdir -p /tmp/ransomware_test
for i in {1..20}; do
    echo "encrypted" > /tmp/ransomware_test/file_$i.enc
done
echo "Triggered! The EDR should have detected the .enc files and triggered a ZFS rollback."

echo -e "\n[7] Simulating Sandbox Escape (Privilege Escalation)..."
# Simulate a browser spawning a root process using sudo
# We will rename bash to firefox locally and run it as root
cp /bin/bash /tmp/firefox
echo "Running dummy process as root under the name 'firefox'..."
sudo /tmp/firefox -c "echo 'Exploit successful?'" 2>/dev/null
echo "Triggered! Check EDR logs for PRIVILEGE_ESCALATION_TRAP."
rm /tmp/firefox

echo -e "\n[8] Simulating EDR Assassination (Agent Self-Defense)..."
# Find the EDR PID
EDR_PID=$(pgrep -f "alphvdr-agent" | head -n 1)
if [ -n "$EDR_PID" ]; then
    echo "Found ALPHVDR at PID $EDR_PID. Attempting assassination..."
    sudo kill -9 $EDR_PID 2>/dev/null
    echo "Triggered! Your current bash session might be frozen (SIGSTOP) right now!"
else
    echo "ALPHVDR not found."
fi

echo -e "\n✅ RED TEAM SIMULATION COMPLETE."
echo "If ALPHVDR is running, several of the above commands should have been completely blocked and frozen by the kernel!"
