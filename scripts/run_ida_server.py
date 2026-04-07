import subprocess

from autoyara.config import settings


def run_server():
    server_cmd = settings.server_cmd
    print("[*] Starting IDA MCP Server...")
    print(f"[*] Server command: {' '.join(server_cmd)}")
    print(f"[*] Python path: {settings.python_path}")
    print(f"[*] IDA path: {settings.ida_path}")
    try:
        subprocess.run(server_cmd, check=True)
    except KeyboardInterrupt:
        print("\n[*] Stopping IDA MCP Server...")
    except Exception as e:
        print(f"[!] Error starting IDA MCP Server: {e}")


if __name__ == "__main__":
    run_server()
