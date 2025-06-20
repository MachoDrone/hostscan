# To install Python 3 on Ubuntu: sudo apt-get install -y python3

import subprocess
import threading
from queue import Queue

# CONFIGURATION
password = "Mac-2341"
user = "md"
subnet = "192.168.0.1/24"
threads = 32

csv_header = (
    "hostname,ip,wallet,,platform,ubuntu_version,genuine_ubuntu,ping_rtt,"
    "nvidia_driver,cuda_version,gpu_model,vram,ram,storage,storage_type,"
    "cpu,node_ver,npm_ver,docker_ver,podman_ver"
)

output_file = "scanhosts.csv"

with open(output_file, "w") as f:
    f.write(csv_header + "\n")

for pkg in ["nmap", "sshpass"]:
    if subprocess.call(f"dpkg -s {pkg} >/dev/null 2>&1", shell=True) != 0:
        subprocess.check_call(f"sudo apt-get install -y {pkg}", shell=True)

nmap_cmd = f"sudo nmap -sn {subnet} -oG -"
ips = []
for line in subprocess.check_output(nmap_cmd, shell=True).decode().splitlines():
    if "Up" in line:
        parts = line.split()
        for part in parts:
            if part.count('.') == 3:
                ips.append(part)
with open("iplist.txt", "w") as f:
    f.write('\n'.join(ips))

print()
print("---scanning---")

def get_host_wallet(ip):
    try:
        ssh_cmd = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"{user}@{ip} \"hostname && docker logs nosana-node 2>/dev/null | head -12 | grep 'Wallet:' | awk '{{print \\$2}}'\" 2>/dev/null"
        )
        output = subprocess.check_output(ssh_cmd, shell=True, timeout=20).decode().splitlines()
        if len(output) >= 2:
            hostname = output[0].strip()
            wallet = output[1].strip()
            return hostname, ip, wallet
        elif len(output) == 1:
            hostname = output[0].strip()
            return hostname, ip, "__FAILED__"
        else:
            return "__FAILED__", ip, "__FAILED__"
    except Exception:
        return "__FAILED__", ip, "__FAILED__"

def worker():
    while True:
        ip = q.get()
        if ip is None:
            break

        hostname, ip_addr, wallet = get_host_wallet(ip)
        if hostname == "__FAILED__":
            q.task_done()
            continue

        remote_script = r'''
fail="__FAILED__"
not_inst="__NOT_INSTALLED__"
na="__N/A__"

for dep in nvidia-smi lscpu lsblk node npm docker; do
    if ! command -v $dep >/dev/null 2>&1; then
        if [ "$dep" = "nvidia-smi" ]; then continue; fi
        if [ "$dep" = "docker" ]; then
            sudo apt-get update -y >/dev/null 2>&1
            sudo apt-get install -y docker.io >/dev/null 2>&1
        else
            sudo apt-get update -y >/dev/null 2>&1
            sudo apt-get install -y $dep >/dev/null 2>&1
        fi
    fi
done

platform="Linux"
if grep -qi microsoft /proc/version 2>/dev/null; then
    platform="WSL-2"
fi

if [ -f /etc/os-release ]; then
    . /etc/os-release
    if echo "$ID $NAME $PRETTY_NAME" | grep -iq ubuntu; then
        ubuntu_version="${VERSION_ID:-$fail}"
        genuine="yes"
    else
        platform="fork "
        ubuntu_version="$fail"
        genuine="no"
    fi
else
    platform="fork "
    ubuntu_version="$fail"
    genuine="no"
fi

# Robust ping RTT detection
ping_rtt="$fail"
ping_out=$(ping -c 5 -w 7 google.com 2>/dev/null)
if [ $? -eq 0 ]; then
    rtt_line=$(echo "$ping_out" | grep 'rtt min/avg/max/mdev' || echo "$ping_out" | grep 'round-trip min/avg/max')
    if [ -n "$rtt_line" ]; then
        rtt_vals=$(echo "$rtt_line" | awk -F' = ' '{print $2}' | awk '{print $1}')
        min=$(echo $rtt_vals | awk -F'/' '{print $1}')
        avg=$(echo $rtt_vals | awk -F'/' '{print $2}')
        max=$(echo $rtt_vals | awk -F'/' '{print $3}')
        mdev=$(echo $rtt_vals | awk -F'/' '{print $4}')
        ping_rtt="min:$min avg:$avg max:$max mdev:$mdev"
    fi
else
    ping_out=$(ping -c 5 -w 7 8.8.8.8 2>/dev/null)
    if [ $? -eq 0 ]; then
        rtt_line=$(echo "$ping_out" | grep 'rtt min/avg/max/mdev' || echo "$ping_out" | grep 'round-trip min/avg/max')
        if [ -n "$rtt_line" ]; then
            rtt_vals=$(echo "$rtt_line" | awk -F' = ' '{print $2}' | awk '{print $1}')
            min=$(echo $rtt_vals | awk -F'/' '{print $1}')
            avg=$(echo $rtt_vals | awk -F'/' '{print $2}')
            max=$(echo $rtt_vals | awk -F'/' '{print $3}')
            mdev=$(echo $rtt_vals | awk -F'/' '{print $4}')
            ping_rtt="min:$min avg:$avg max:$max mdev:$mdev"
        fi
    fi
fi
[ -z "$ping_rtt" ] && ping_rtt="$fail"

ram_kb=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}')
if [ -n "$ram_kb" ]; then
    ram_gb=$(echo $ram_kb | awk '{printf("%'\''d GB", $1/1024/1024)}' | sed "s/'/,/g")
else
    ram_gb="$fail"
fi

rootdev=$(df / | awk 'NR==2{print $1}' | sed 's|/dev/||')
parentdev=$(lsblk -no PKNAME /dev/$rootdev 2>/dev/null)
if [ -z "$parentdev" ]; then
    parentdev=$rootdev
fi

if [ -n "$parentdev" ]; then
    storage_info=$(lsblk -d -o NAME,SIZE,MODEL,ROTA,TRAN | awk -v dev="$parentdev" '$1==dev')
    dev_name=$(echo "$storage_info" | awk '{print $1}')
    dev_size=$(echo "$storage_info" | awk '{print $2}')
    dev_model=$(echo "$storage_info" | awk '{print $3}')
    dev_rota=$(echo "$storage_info" | awk '{print $4}')
    dev_tran=$(echo "$storage_info" | awk '{print $5}')
    storage="$dev_size $dev_model"
    if [[ "$dev_name" == nvme* ]]; then
        storage_type="NVMe"
    elif [[ "$dev_model" =~ [Ss][Ss][Dd] ]]; then
        storage_type="SSD"
    elif [[ "$dev_model" =~ [Hh][Dd][Dd] || "$dev_model" =~ ^ST ]]; then
        storage_type="HDD"
    elif [ "$dev_tran" = "nvme" ]; then
        storage_type="NVMe"
    elif [ "$dev_tran" = "sata" ] && [ "$dev_rota" = "0" ]; then
        storage_type="SSD"
    elif [ "$dev_tran" = "sata" ] && [ "$dev_rota" = "1" ]; then
        storage_type="HDD"
    elif [ "$dev_tran" = "usb" ]; then
        storage_type="USB"
    elif [ "$dev_rota" = "0" ]; then
        storage_type="SSD"
    elif [ "$dev_rota" = "1" ]; then
        storage_type="HDD"
    else
        storage_type="Unknown"
    fi
else
    storage="$not_inst"
    storage_type="$not_inst"
fi

if command -v lscpu >/dev/null 2>&1; then
    cpu=$(lscpu | grep 'Model name' | awk -F: '{print $2}' | xargs)
    [ -z "$cpu" ] && cpu="$fail"
else
    cpu="$not_inst"
fi

if command -v node >/dev/null 2>&1; then
    node_ver=$(node -v 2>/dev/null)
else
    node_ver="$not_inst"
fi

if command -v npm >/dev/null 2>&1; then
    npm_ver=$(npm -v 2>/dev/null)
else
    npm_ver="$not_inst"
fi

if command -v docker >/dev/null 2>&1; then
    docker_ver=$(docker -v 2>/dev/null | awk '{print $3}' | sed 's/,//')
else
    docker_ver="$not_inst"
fi

if [ "$platform" = "WSL-2" ]; then
    if command -v podman >/dev/null 2>&1; then
        podman_ver=$(podman -v 2>/dev/null)
    else
        podman_ver="$not_inst"
    fi
else
    if command -v docker >/dev/null 2>&1; then
        podman_ver=$(docker exec podman podman -v 2>/dev/null)
        [ -z "$podman_ver" ] && podman_ver="$fail"
    else
        podman_ver="$not_inst"
    fi
fi

# Per-GPU output
if command -v nvidia-smi >/dev/null 2>&1; then
    nvidia_driver=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)
    cuda_version=$(nvidia-smi 2>/dev/null | grep "CUDA Version" | awk '{print $9}' | head -1)
    nvidia_smi_out=$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null)
    gpu_idx=0
    echo "$nvidia_smi_out" | while IFS=, read -r gpu_model vram_mb; do
        gpu_model=$(echo "$gpu_model" | xargs)
        vram_mb=$(echo "$vram_mb" | awk '{print $1}')
        if [ -n "$vram_mb" ]; then
            vram_gb=$(echo $vram_mb | awk '{printf("%'\''d GB", $1/1024)}' | sed "s/'/,/g")
        else
            vram_gb="$fail"
        fi
        echo ",${platform},${ubuntu_version},${genuine},${ping_rtt},${nvidia_driver},${cuda_version},${gpu_model},${vram_gb},${ram_gb},${storage},${storage_type},${cpu},${node_ver},${npm_ver},${docker_ver},${podman_ver}"
        gpu_idx=$((gpu_idx+1))
    done
    if [ "$gpu_idx" -eq 0 ]; then
        echo ",${platform},${ubuntu_version},${genuine},${ping_rtt},${nvidia_driver},${cuda_version},${not_inst},${not_inst},${ram_gb},${storage},${storage_type},${cpu},${node_ver},${npm_ver},${docker_ver},${podman_ver}"
    fi
else
    echo ",${platform},${ubuntu_version},${genuine},${ping_rtt},${not_inst},${not_inst},${not_inst},${not_inst},${ram_gb},${storage},${storage_type},${cpu},${node_ver},${npm_ver},${docker_ver},${podman_ver}"
fi
'''

        ssh_cmd = (
            f"sshpass -p '{password}' ssh "
            f"-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
            f"{user}@{ip} 'bash -s' 2>/dev/null"
        )

        try:
            result = subprocess.check_output(ssh_cmd, input=remote_script.encode(), shell=True, timeout=90).decode().strip()
            if result:
                for line in result.splitlines():
                    full_line = f"{hostname},{ip_addr},{wallet}{line}"
                    print(full_line, flush=True)
                    with lock:
                        with open(output_file, "a") as f:
                            f.write(full_line + "\n")
        except Exception:
            pass
        q.task_done()

q = Queue()
lock = threading.Lock()
for ip in ips:
    q.put(ip)
threads_list = []
for _ in range(threads):
    t = threading.Thread(target=worker)
    t.start()
    threads_list.append(t)
q.join()
for _ in threads_list:
    q.put(None)
for t in threads_list:
    t.join()

# Deduplicate, filter, and count hosts
with open(output_file) as f:
    lines = [line.strip() for line in f if line.strip()]
header = lines[0]
data_lines = [line for line in lines[1:] if not line.startswith("hostname,ip,wallet")]
filtered_lines = []
for line in data_lines:
    fields = line.split(",")
    if len(fields) > 11 and not (fields[9] == "__NOT_INSTALLED__" and fields[10] == "__NOT_INSTALLED__"):
        filtered_lines.append(line)
unique_lines = sorted(set(filtered_lines))
with open(output_file, "w") as f:
    f.write(header + "\n")
    for line in unique_lines:
        f.write(line + "\n")

print("Scan complete.")
print(f"\n--- {len(unique_lines)} GPU/host lines with reported information ---")
print(f"\n--- {output_file} (deduplicated, sorted by hostname) ---")
with open(output_file) as f:
    print(f.read())
