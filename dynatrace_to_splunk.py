import requests
import time
import json
import uuid

# === CONFIG ===
DT_ENV = "wqn62457"
DT_TOKEN = "dt0c01.TCMNJHE577SR7IIMMYFJCX7Q.3WIIFXYAUURZADBKPLOWTVKXXLGHTT4F6CKRJ6RRZV52RB34WPU7ZKLJ7YHTN536"
SPLUNK_HEC_URL = "http://localhost:8088/services/collector/event"
SPLUNK_HEC_TOKEN = "014dd259-eb13-457c-bc68-d20face0d0f1"
DT_BASE = f"https://{DT_ENV}.live.dynatrace.com/api/v2"

HEADERS_DT = {"Authorization": f"Api-Token {DT_TOKEN}"}
HEADERS_SPLUNK = {
    "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
    "Content-Type": "application/json",
    "X-Splunk-Request-Channel": str(uuid.uuid4())
}

def get_dynatrace_problems():
    url = f"{DT_BASE}/problems?pageSize=10&problemSelector=status(OPEN)"
    r = requests.get(url, headers=HEADERS_DT)
    return r.json().get("problems", [])

def get_dynatrace_metrics():
    url = f"{DT_BASE}/metrics/query?metricSelector=builtin:host.cpu.usage,builtin:host.mem.usage&resolution=1m"
    r = requests.get(url, headers=HEADERS_DT)
    return r.json().get("resolution", {})

def send_to_splunk(event_data, sourcetype="dynatrace:event"):
    payload = {
        "event": event_data,
        "sourcetype": sourcetype
    }
    r = requests.post(SPLUNK_HEC_URL, headers=HEADERS_SPLUNK, json=payload)
    return r.json()

def run():
    print("🚀 Dynatrace → Splunk forwarder started...")
    while True:
        print("\n⏱ Fetching Dynatrace problems...")
        problems = get_dynatrace_problems()
        
        if problems:
            for p in problems:
                event = {
                    "source": "dynatrace",
                    "type": "problem",
                    "problem_id": p.get("problemId"),
                    "title": p.get("title"),
                    "severity": p.get("severityLevel"),
                    "status": p.get("status"),
                    "impacted_entities": [e.get("name") for e in p.get("impactedEntities", [])],
                    "root_cause": p.get("rootCauseEntity", {}).get("name", "unknown")
                }
                result = send_to_splunk(event, "dynatrace:problem")
                print(f"  ✅ Problem sent: {event['title']} → {result}")
        else:
            # Send a heartbeat so Splunk always has data
            event = {
                "source": "dynatrace",
                "type": "heartbeat",
                "status": "healthy",
                "message": "No open problems"
            }
            send_to_splunk(event, "dynatrace:heartbeat")
            print("  💚 Heartbeat sent — no open problems")

        print("⏳ Waiting 60 seconds...")
        time.sleep(60)

if __name__ == "__main__":
    run()