import subprocess
from config import CONFIG

def stream_logs():
    process = subprocess.Popen(
        ["sudo", "tail", "-F", CONFIG["auth_log_path"]],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    print("🚀 Real-time log streaming started...\n")

    for line in process.stdout:
        yield line.strip()
