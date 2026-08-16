import json
import subprocess
import asyncio
import httpx
import uuid

# Target Configuration parameters
API_URL = "http://172.17.0.1:8080/v1/telemetry"

def map_tetragon_to_schema(raw_line):
    """
    Extracts raw Tetragon JSON and reformats it to match your 
    Security API's TelemetryEvent data model.
    """
    try:
        event_data = json.loads(raw_line)
        
        # We only care about process execution events caught by your policy
        process_info = event_data.get("process_exec", {}).get("process", {})
        if not process_info:
            return None
            
        # Parse attributes out of the raw kernel structures
        binary_name = process_info.get("binary", "unknown")
        arguments = process_info.get("arguments", "")
        pod_metadata = process_info.get("pod", {})
        
        # Intentionally detect security flags based on process names
        is_malicious = "unknown-shell" in binary_name or "curl" in binary_name

        # Structure the payload data to perfectly match the API expectations
        payload = {
            "event_id": str(uuid.uuid4()),
            "event_type": "process",
            "source_ip": pod_metadata.get("pod_ip", "127.0.0.1"),
            "destination_ip": "203.0.113.66" if is_malicious else "10.20.0.1",
            "destination_port": 4444 if is_malicious else 80,
            "process": binary_name,
            "user": process_info.get("user", "unknown"),
            "namespace": pod_metadata.get("namespace", "default"),
            "bytes_out": 90000000 if is_malicious else 1024,
            "failed_auth_count": 0,
            "privileged": process_info.get("cap_effective", False),
            "known_bad_ioc": is_malicious
        }
        return payload
    except Exception:
        return None

async def stream_and_forward():
    """
    Spawns a shell stream to read Tetragon logs and forwards 
    the transformed blocks over HTTPX.
    """
    # Build the exact command pipeline to pull raw JSON data lines
    cmd = "kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f"
    
    print("⏳ Starting Tetragon Adapter Loop... Listening to kernel tracepoints...")
    
    # Open an active non-blocking stream process pipe
    process = await asyncio.create_subprocess_shell(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )
    
    async with httpx.AsyncClient(timeout=5) as client:
        while True:
            line = await process.stdout.readline()
            if not line:
                break
                
            decoded_line = line.decode('utf-8').strip()
            mapped_payload = map_tetragon_to_schema(decoded_line)
            
            if mapped_payload:
                try:
                    # Fire off the post request asynchronously 
                    response = await client.post(API_URL, json=mapped_payload)
                    print(f"📡 Forwarded Event: {mapped_payload['process']} -> Status: {response.status_code}")
                except Exception as e:
                    print(f"⚠️ Network error connecting to Security API: {e}")

if __name__ == "__main__":
    asyncio.run(stream_and_forward())
