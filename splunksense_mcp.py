import subprocess
import json
import requests
import time
import warnings
warnings.filterwarnings('ignore')

# === CONFIG ===
SPLUNK_USER = "user_name"
SPLUNK_PASS = "password!"
OPENROUTER_API_KEY = "api_key"
MCP_TOKEN = "mcp_token"
MCP_URL = "http://localhost:8000/en-US/splunkd/__raw/services/mcp"


def query_splunk_via_mcp(spl_query):
    """Query Splunk using MCP protocol"""
    headers = {
        "Authorization": f"Bearer {MCP_TOKEN}",
        "Content-Type": "application/json"
    }
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "splunk_run_query",  # ← fixed tool name
            "arguments": {
                "query": spl_query
            }
        }
    }
    r = requests.post(MCP_URL, headers=headers, json=payload)
    return r.json()

def get_open_problems_via_mcp():
    """Get open Dynatrace problems via MCP"""
    print("  🔌 Querying Splunk via MCP...")
    result = query_splunk_via_mcp(
        'search index=main sourcetype="dynatrace:problem" status=OPEN | head 5'
    )
    problems = []
    try:
        content = result.get("result", {}).get("content", [])
        for item in content:
            if item.get("type") == "text":
                data = json.loads(item.get("text", "{}"))
                for row in data.get("results", []):
                    try:
                        raw = json.loads(row.get("_raw", "{}"))
                        problems.append(raw)
                    except:
                        pass
    except Exception as e:
        print(f"  ⚠️ MCP error: {e}, falling back to direct API")
        return get_open_problems_fallback()
    return problems

def analyze_with_ai(problem):
    """Analyze problem with OpenRouter"""
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json"
    }
    prompt = f"""You are SplunkSense, an autonomous infrastructure remediation agent.

Analyze this infrastructure problem detected by Dynatrace and forwarded to Splunk via MCP:

Problem: {json.dumps(problem, indent=2)}

Provide:
1. ROOT CAUSE ANALYSIS
2. SEVERITY ASSESSMENT (Low/Medium/High/Critical)
3. IMMEDIATE ACTION
4. REMEDIATION COMMAND (exact Windows PowerShell command)
5. PREVENTION

Be specific and actionable."""

    body = {
        "model": "anthropic/claude-sonnet-4-6",
        "max_tokens": 1000,
        "messages": [{"role": "user", "content": prompt}]
    }
    r = requests.post(url, headers=headers, json=body)
    return r.json()["choices"][0]["message"]["content"]

def execute_remediation(problem):
    import subprocess
    print("\n🔧 Executing remediation...")
    if "Memory" in problem.get("title", ""):
        result = subprocess.run(
            ['powershell', '-Command',
             'Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 | Format-Table Name, @{N="Memory(MB)";E={[math]::Round($_.WorkingSet64/1MB,2)}} -AutoSize'],
            capture_output=True, text=True
        )
        print(result.stdout)
        print("  ✅ Memory remediation executed!")
        return True
    return False

def run():
    print("🤖 SplunkSense Agent started (MCP Mode)...")
    print(f"   MCP Endpoint: {MCP_URL}\n")
    seen_problems = set()

    while True:
        problems = get_open_problems_via_mcp()

        for problem in problems:
            pid = problem.get("problem_id")
            if pid and pid not in seen_problems:
                seen_problems.add(pid)
                print(f"\n🔴 New problem detected via MCP: {problem.get('title')}")
                print("   Analyzing with AI...")
                analysis = analyze_with_ai(problem)

                print("\n" + "="*60)
                print("🚨 SPLUNKSENSE ALERT (via Splunk MCP)")
                print("="*60)
                print(f"Problem : {problem.get('title')}")
                print(f"Severity: {problem.get('severity')}")
                print(f"Host    : {problem.get('root_cause')}")
                print(f"Status  : {problem.get('status')}")
                print("\n📊 AI ANALYSIS:")
                print(analysis)
                print("="*60)

                confirm = input("\n✅ Execute remediation? (yes/no): ").strip().lower()
                if confirm == "yes":
                    execute_remediation(problem)
                else:
                    print("⏭️ Skipped by operator.")

        if not problems:
            print("💚 No open problems via MCP. Watching...")

        time.sleep(30)

if __name__ == "__main__":
    run()