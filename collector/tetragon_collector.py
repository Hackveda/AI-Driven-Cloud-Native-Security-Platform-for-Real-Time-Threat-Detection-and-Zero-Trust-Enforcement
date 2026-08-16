from __future__ import annotations
import json,os,time,threading
import httpx
from kubernetes import client,config

API=os.getenv("SOC_API_URL","http://security-api.default.svc.cluster.local/v1/tetragon")
NS=os.getenv("TETRAGON_NAMESPACE","kube-system")
LABEL=os.getenv("TETRAGON_LABEL","app.kubernetes.io/name=tetragon")
CONTAINER=os.getenv("TETRAGON_CONTAINER","export-stdout")
CLUSTER=os.getenv("CLUSTER_NAME","kubernetes-cluster")

def cfg():
    try:config.load_incluster_config()
    except config.ConfigException:config.load_kube_config()

def stream_pod(name):
    api=client.CoreV1Api()
    with httpx.Client(timeout=10) as http:
        while True:
            try:
                log=api.read_namespaced_pod_log(name=name,namespace=NS,container=CONTAINER,follow=True,timestamps=False,_preload_content=False)
                for raw in log.stream():
                    try:
                        e=json.loads(raw.decode(errors="replace").strip()); e["_soc_cluster_name"]=CLUSTER
                        http.post(API,json=e).raise_for_status()
                    except json.JSONDecodeError:pass
                    except Exception as ex:print(name,ex,flush=True)
            except Exception as ex:
                print(f"{name} stream reconnect: {ex}",flush=True); time.sleep(3)

def main():
    cfg(); api=client.CoreV1Api(); started=set()
    while True:
        try:
            pods=api.list_namespaced_pod(NS,label_selector=LABEL).items
            for p in pods:
                name=p.metadata.name
                if p.status.phase=="Running" and name not in started:
                    threading.Thread(target=stream_pod,args=(name,),daemon=True).start(); started.add(name)
            time.sleep(10)
        except Exception as ex:
            print("discovery error",ex,flush=True); time.sleep(5)
if __name__=="__main__":main()
