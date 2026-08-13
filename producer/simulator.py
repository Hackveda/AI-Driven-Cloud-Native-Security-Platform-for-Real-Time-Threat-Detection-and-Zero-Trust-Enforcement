import argparse, asyncio, random, time, uuid
import httpx

async def main(base: str, count: int, direct: bool):
    endpoint = base.rstrip('/') + ('/v1/evaluate' if direct else '/v1/telemetry')
    async with httpx.AsyncClient(timeout=10) as c:
        for i in range(count):
            malicious = i % 7 == 6
            payload = {
              "event_id": str(uuid.uuid4()), "event_type": random.choice(["network","process","auth","k8s"]),
              "source_ip": f"10.0.1.{random.randint(2,240)}", "destination_ip": "203.0.113.66" if malicious else f"10.20.0.{random.randint(2,240)}",
              "destination_port": 4444 if malicious else random.choice([22,53,80,443,5432]),
              "process": "unknown-shell" if malicious else random.choice(["nginx","python","java","node"]),
              "user": "root" if malicious else "svc-app", "namespace":"payments",
              "bytes_out": 90000000 if malicious else random.randint(200, 200000),
              "failed_auth_count": 9 if malicious else random.choice([0,0,0,1]),
              "privileged": malicious, "known_bad_ioc": malicious
            }
            r = await c.post(endpoint, json=payload); print(r.status_code, r.text[:260]); await asyncio.sleep(.35)

if __name__ == '__main__':
    p=argparse.ArgumentParser(); p.add_argument('--base',default='http://localhost:8080'); p.add_argument('--count',type=int,default=20); p.add_argument('--direct',action='store_true')
    a=p.parse_args(); asyncio.run(main(a.base,a.count,a.direct))
