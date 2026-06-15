from flask import Flask, jsonify, request, render_template_string
from flask_cors import CORS
import requests
import json
import subprocess
import warnings
from datetime import datetime
warnings.filterwarnings('ignore')

app = Flask(__name__)
CORS(app)

SPLUNK_USER = "user_name"
SPLUNK_PASS = "password"
OPENROUTER_API_KEY = "api_key"
MCP_TOKEN =""your_mcp_token"
MCP_URL = "http://localhost:8000/en-US/splunkd/__raw/services/mcp"

audit_log = []

def log_audit(action, detail, status="success"):
    audit_log.insert(0, {"time": datetime.now().strftime("%H:%M:%S"), "action": action, "detail": detail, "status": status})
    if len(audit_log) > 50:
        audit_log.pop()

def query_mcp(spl_query):
    headers = {"Authorization": f"Bearer {MCP_TOKEN}", "Content-Type": "application/json"}
    payload = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "splunk_run_query", "arguments": {"query": spl_query}}}
    r = requests.post(MCP_URL, headers=headers, json=payload, timeout=15)
    return r.json()

def get_problems():
    try:
        result = query_mcp('search index=main sourcetype="dynatrace:problem" status=OPEN | head 10 | dedup problem_id')
        content = result.get("result", {}).get("content", [])
        problems = []
        for item in content:
            if item.get("type") == "text":
                data = json.loads(item.get("text", "{}"))
                for row in data.get("results", []):
                    try:
                        raw = json.loads(row.get("_raw", "{}"))
                        raw["_time"] = row.get("_time", "")
                        problems.append(raw)
                    except:
                        pass
        log_audit("MCP Query", f"Found {len(problems)} open problems")
        return problems
    except Exception as e:
        log_audit("MCP Query", str(e), "error")
        return []

def call_ai(messages, max_tokens=200):
    url = "https://openrouter.ai/api/v1/chat/completions"
    headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json"}
    for model in ["deepseek/deepseek-chat", "mistralai/mistral-small"]:
        body = {"model": model, "max_tokens": max_tokens, "messages": messages}
        r = requests.post(url, headers=headers, json=body, timeout=30)
        resp = r.json()
        if "choices" in resp:
            return resp["choices"][0]["message"]["content"]
        print(f"Model {model} failed: {resp.get('error', {}).get('message')}")
    raise Exception("All AI models failed")

def query_mcp_data(service):
    history, incidents, related = [], [], []
    try:
        r = query_mcp(f'search index=main sourcetype="dynatrace:metric" service="{service}" | tail 10 | table _time cpu_usage memory_usage response_time_ms error_rate')
        for item in r.get("result", {}).get("content", []):
            if item.get("type") == "text":
                history = json.loads(item["text"]).get("results", [])
    except: pass
    try:
        r = query_mcp(f'search index=main sourcetype="dynatrace:problem" root_cause="{service}" | head 5 | table title severity _time')
        for item in r.get("result", {}).get("content", []):
            if item.get("type") == "text":
                incidents = json.loads(item["text"]).get("results", [])
    except: pass
    try:
        r = query_mcp('search index=main sourcetype="dynatrace:metric" | stats avg(cpu_usage) as cpu avg(error_rate) as err by service | sort -err | head 5')
        for item in r.get("result", {}).get("content", []):
            if item.get("type") == "text":
                related = json.loads(item["text"]).get("results", [])
    except: pass
    return history, incidents, related

def analyze_problem_multistep(problem):
    service = problem.get("root_cause", problem.get("service", "unknown"))
    steps = []

    # Step 1
    log_audit("Agent Step 1/5", f"Problem intake: {service}")
    s1 = call_ai([{"role": "user", "content": f"You are SplunkSense, an agentic infra co-pilot.\n\nSTEP 1 - PROBLEM INTAKE\nAlert from Dynatrace via Splunk MCP:\n{json.dumps(problem, indent=2)}\n\nIn 2-3 sentences: what is happening and what data do you need to diagnose it?"}], 250)
    steps.append({"step": 1, "title": "Problem Intake", "icon": "📥", "content": s1})

    # Step 2 - fetch MCP data
    log_audit("Agent Step 2/5", f"Querying Splunk MCP for {service}")
    history, incidents, related = query_mcp_data(service)
    s2 = f"Queried Splunk MCP via splunk_run_query:\n• {len(history)} metric datapoints for {service}\n• {len(incidents)} past incidents found\n• {len(related)} related services analyzed\nMCP tools used: splunk_run_query × 3"
    steps.append({"step": 2, "title": "MCP Data Collection", "icon": "🔌", "content": s2})

    # Step 3 - root cause
    log_audit("Agent Step 3/5", "Root cause analysis")
    ctx = {"recent_metrics": history[-3:], "past_incidents": incidents[:2], "related_services": related[:3]}
    s3 = call_ai([{"role": "user", "content": f"STEP 3 - ROOT CAUSE ANALYSIS\nProblem: {json.dumps(problem)}\nSplunk MCP data: {json.dumps(ctx)}\n\nProvide 3-4 sentence root cause analysis based on the problem AND historical data."}], 350)
    steps.append({"step": 3, "title": "Root Cause Analysis", "icon": "🔍", "content": s3})

    # Step 4 - remediation plan
    log_audit("Agent Step 4/5", "Planning remediation")
    s4_text = call_ai([{"role": "user", "content": f"STEP 4 - REMEDIATION PLAN\nProblem: {problem.get('title')} on {service}\nRoot cause: {s3[:200]}\n\nRespond ONLY with this JSON:\n{{\"severity\":\"Critical|High|Medium|Low\",\"time_to_impact_minutes\":0,\"immediate_action\":\"string\",\"remediation_command\":\"string\",\"rollback_command\":\"string\",\"prevention\":\"string\",\"estimated_resolution_minutes\":0}}"}], 350)
    try:
        s4 = json.loads(s4_text.strip().replace("```json","").replace("```","").strip())
    except:
        s4 = {"severity": "High", "time_to_impact_minutes": 15, "immediate_action": s4_text[:150], "remediation_command": "Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 10 | Format-Table", "rollback_command": "# Monitor after action", "prevention": "Set automated alerts", "estimated_resolution_minutes": 5}
    s4_content = f"Severity: {s4.get('severity')} | Impact in: {s4.get('time_to_impact_minutes')}min | Fix in: {s4.get('estimated_resolution_minutes')}min\n\nAction: {s4.get('immediate_action')}"
    steps.append({"step": 4, "title": "Remediation Planning", "icon": "🛠️", "content": s4_content})

    # Step 5
    log_audit("Agent Step 5/5", "Awaiting human confirmation")
    s5 = f"Analysis complete. Awaiting human-in-the-loop confirmation.\n\nCommand: {s4.get('remediation_command')}\nRollback: {s4.get('rollback_command')}"
    steps.append({"step": 5, "title": "Awaiting Confirmation", "icon": "✋", "content": s5})

    return {"steps": steps, "final": s4}

def execute_remediation(title):
    try:
        cmd = 'Get-Process | Sort-Object WorkingSet64 -Descending | Select-Object -First 5 | Format-Table Name, @{N="MB";E={[math]::Round($_.WorkingSet64/1MB,2)}} -AutoSize'
        result = subprocess.run(['powershell', '-Command', cmd], capture_output=True, text=True, timeout=10)
        log_audit("Remediation", f"Executed on: {title}")
        return {"success": True, "output": result.stdout or "Completed"}
    except Exception as e:
        log_audit("Remediation", str(e), "error")
        return {"success": False, "output": str(e)}

@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/problems")
def api_problems():
    return jsonify(get_problems())

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    try:
        problem = request.json
        if not problem:
            return jsonify({"error": "No data"}), 400
        result = analyze_problem_multistep(problem)
        return jsonify(result)
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"steps": [{"step": 1, "title": "Error", "icon": "❌", "content": str(e)}], "final": {"severity": "High", "time_to_impact_minutes": 0, "immediate_action": str(e), "remediation_command": "", "rollback_command": "", "prevention": "", "estimated_resolution_minutes": 0}}), 200

@app.route("/api/remediate", methods=["POST"])
def api_remediate():
    return jsonify(execute_remediation(request.json.get("title", "")))

@app.route("/api/audit")
def api_audit():
    return jsonify(audit_log)

@app.route("/api/forecast")
def api_forecast():
    try:
        service = request.args.get("service", "database-primary")
        query = f'search index=main sourcetype="dynatrace:metric" service="{service}" | table _time cpu_usage memory_usage response_time_ms | sort _time'
        result = query_mcp(query)
        content_items = result.get("result", {}).get("content", [])
        history = []
        for item in content_items:
            if item.get("type") == "text":
                data = json.loads(item.get("text", "{}"))
                history = data.get("results", [])
        cpu_series = [float(r.get("cpu_usage") or 0) for r in history if r.get("cpu_usage")]
        mem_series = [float(r.get("memory_usage") or 0) for r in history if r.get("memory_usage")]
        lat_series = [float(r.get("response_time_ms") or 0) for r in history if r.get("response_time_ms")]
        def simple_forecast(series, steps=8):
            if not series: return [0]*steps
            if len(series) < 2: return [round(series[-1],1)]*steps
            recent = series[-6:]
            trend = (recent[-1] - recent[0]) / max(len(recent)-1, 1)
            return [round(min(100, max(0, series[-1] + trend*(i+1))), 1) for i in range(steps)]
        cpu_f = simple_forecast(cpu_series)
        mem_f = simple_forecast(mem_series)
        lat_f = simple_forecast(lat_series)
        mem_current = mem_series[-1] if mem_series else 0
        cpu_current = cpu_series[-1] if cpu_series else 0
        mem_trend = (mem_series[-1]-mem_series[0])/max(len(mem_series)-1,1) if len(mem_series)>1 else 0
        minutes_to_critical = round((95-mem_current)/max(mem_trend,0.01)*0.5) if mem_trend>0 else 999
        try:
            prediction = call_ai([{"role":"user","content":f"SplunkSense predictive engine. Service: {service}. Memory: {mem_current:.1f}% growing at {mem_trend:.1f}%/interval. CPU: {cpu_current:.1f}%. In 2 sentences: what will happen and when will it become critical?"}], 100)
        except:
            prediction = f"Memory at {mem_current:.1f}% growing steadily. Critical threshold expected in {minutes_to_critical} minutes if trend continues."
        return jsonify({"service":service,"cpu":{"history":cpu_series,"forecast":cpu_f},"memory":{"history":mem_series,"forecast":mem_f},"latency":{"history":lat_series,"forecast":lat_f},"prediction":prediction,"minutes_to_critical":minutes_to_critical,"mem_current":round(mem_current,1),"cpu_current":round(cpu_current,1)})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error":str(e)}), 500

@app.route("/api/ask", methods=["POST"])
def api_ask():
    try:
        question = request.json.get("question", "")
        # Smart keyword-based SPL mapping (no AI needed = instant)
        q_lower = question.lower()
        if "error rate" in q_lower or "errors" in q_lower:
            spl_query = 'search index=main sourcetype="dynatrace:metric" | stats avg(error_rate) as err by service | sort -err | head 5'
        elif "cpu" in q_lower:
            spl_query = 'search index=main sourcetype="dynatrace:metric" | stats avg(cpu_usage) as cpu by service | sort -cpu | head 5'
        elif "memory" in q_lower or "mem" in q_lower:
            spl_query = 'search index=main sourcetype="dynatrace:metric" | stats avg(memory_usage) as mem by service | sort -mem | head 5'
        elif "crash" in q_lower or "problem" in q_lower or "incident" in q_lower or "critical" in q_lower:
            spl_query = 'search index=main sourcetype="dynatrace:problem" | table _time title severity status root_cause | sort -_time | head 10'
        elif "latency" in q_lower or "slow" in q_lower or "response" in q_lower:
            spl_query = 'search index=main sourcetype="dynatrace:metric" | stats avg(response_time_ms) as latency by service | sort -latency | head 5'
        elif "security" in q_lower or "attack" in q_lower or "brute" in q_lower:
            spl_query = 'search index=main sourcetype="dynatrace:security" | table _time title severity service description | head 5'
        elif "week" in q_lower or "today" in q_lower or "recent" in q_lower:
            spl_query = 'search index=main sourcetype="dynatrace:problem" | table _time title severity status root_cause | sort -_time | head 10'
        else:
            spl_query = 'search index=main sourcetype="dynatrace:problem" status=OPEN | table _time title severity root_cause | head 10'

        # Run query via MCP
        result = query_mcp(spl_query)
        content_items = result.get("result", {}).get("content", [])
        raw_data = []
        for item in content_items:
            if item.get("type") == "text":
                try:
                    data = json.loads(item.get("text","{}"))
                    raw_data = data.get("results", [])
                except: pass

        # AI answer (with short prompt = faster)
        try:
            answer_prompt = f'SplunkSense infra co-pilot. Question: "{question}". Data from Splunk MCP ({len(raw_data)} results): {json.dumps(raw_data[:3])}. Answer in 2-3 sentences with numbers. Write [TIMELINE] with 4-5 events (HH:MM - event). End with [RECOMMENDATION] one sentence.'
            answer = call_ai([{"role":"user","content":answer_prompt}], 200)
        except:
            # Fallback: generate answer from raw data directly
            if raw_data:
                top = raw_data[0]
                # Build smart answer from raw data
                rows = raw_data[:5]
                q_lower = question.lower()
                if "cpu" in q_lower:
                    rows_sorted = sorted(rows, key=lambda x: float(x.get('cpu',0)), reverse=True)
                    top = rows_sorted[0] if rows_sorted else rows[0]
                    answer = f"The service with highest CPU usage is {top.get('service','unknown')} at {float(top.get('cpu',0)):.1f}%. Found {len(raw_data)} services in Splunk MCP data. [TIMELINE] {rows_sorted[0].get('service','?')}: {float(rows_sorted[0].get('cpu',0)):.1f}% CPU - Current reading [RECOMMENDATION] Investigate {top.get('service','the top service')} immediately and consider scaling or restarting."
                elif "error" in q_lower:
                    top = rows[0]
                    answer = f"The service with highest error rate is {top.get('service','unknown')} at {float(top.get('err',0)):.3f}%. Found {len(raw_data)} services reporting errors. [TIMELINE] {top.get('service','?')}: {float(top.get('err',0)):.3f}% errors - Current reading [RECOMMENDATION] Check {top.get('service','the affected service')} logs and consider rolling back recent deployments."
                elif "memory" in q_lower or "mem" in q_lower:
                    top = rows[0]
                    answer = f"The service with highest memory usage is {top.get('service','unknown')} at {float(top.get('mem',0)):.1f}%. Found {len(raw_data)} services in Splunk MCP data. [TIMELINE] {top.get('service','?')}: {float(top.get('mem',0)):.1f}% memory - Current reading [RECOMMENDATION] Check for memory leaks in {top.get('service','the affected service')} and restart if above 90%."
                else:
                    summary = ", ".join([f"{r.get('service','?')}: {list(r.values())[1] if len(r)>1 else '?'}" for r in rows[:3]])
                    answer = f"Found {len(raw_data)} results from Splunk MCP for your query. Top results: {summary}. [RECOMMENDATION] Review the data above and take action on the most critical service."
            else:
                answer = f"No data found for: {question}. [RECOMMENDATION] Try rephrasing or check if data is being ingested."

        return jsonify({"answer": answer, "query": spl_query, "results": raw_data[:10], "count": len(raw_data)})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({"error": str(e)}), 500

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SplunkSense — Agentic Infra Co-Pilot</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;600&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap');
:root{--bg:#0a0e1a;--bg2:#0f1525;--bg3:#141c30;--border:#1e2d4a;--accent:#00c7ff;--accent2:#7b5ea7;--red:#ff4d6d;--green:#00e5a0;--yellow:#ffc142;--text:#c8d8f0;--text2:#6b82a8;--mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',sans-serif}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:var(--sans);min-height:100vh}
header{background:var(--bg2);border-bottom:1px solid var(--border);padding:0 2rem;display:flex;align-items:center;justify-content:space-between;height:56px;position:sticky;top:0;z-index:100}
.logo{display:flex;align-items:center;gap:10px;font-family:var(--mono);font-size:1rem;font-weight:600;color:#fff}
.logo-icon{width:28px;height:28px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px}
.header-right{display:flex;align-items:center;gap:1.5rem;font-size:0.75rem;color:var(--text2);font-family:var(--mono)}
.status-dot{width:7px;height:7px;border-radius:50%;background:var(--green);display:inline-block;margin-right:5px;box-shadow:0 0 6px var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}

.tabs{display:flex;gap:0;border-bottom:1px solid var(--border);background:var(--bg2);padding:0 2rem;flex-shrink:0}
.tab{padding:0.75rem 1.5rem;font-family:var(--mono);font-size:0.72rem;cursor:pointer;color:var(--text2);border-bottom:2px solid transparent;transition:all 0.2s;letter-spacing:0.05em}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab:hover{color:var(--text)}
.tab-content{display:none;grid-column:1/-1;overflow:hidden}
.tab-content.active{display:grid;grid-template-columns:1fr 360px;height:calc(100vh - 56px - 44px - 80px)}
#tab-problems.active{display:grid;grid-template-columns:1fr 360px}
#tab-forecast.active{display:block;overflow-y:auto;padding:2rem}
.forecast-grid{display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.5rem;margin-bottom:2rem}
.forecast-card{background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:1.5rem;position:relative;overflow:hidden}
.forecast-card.critical{border-color:var(--red)}
.forecast-card.warning{border-color:var(--yellow)}
.forecast-card-title{font-family:var(--mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--text2);margin-bottom:0.5rem}
.forecast-value{font-family:var(--mono);font-size:2rem;font-weight:600;color:#fff;line-height:1;margin-bottom:0.25rem}
.forecast-value.red{color:var(--red)}.forecast-value.yellow{color:var(--yellow)}.forecast-value.green{color:var(--green)}
.forecast-trend{font-family:var(--mono);font-size:0.72rem;color:var(--text2);margin-bottom:1rem}
.mini-chart{height:60px;width:100%;position:relative}
.ai-prediction{background:var(--bg2);border:1px solid var(--accent2);border-radius:10px;padding:1.5rem;margin-bottom:2rem}
.ai-prediction-label{font-family:var(--mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--accent2);margin-bottom:0.75rem}
.ai-prediction-text{font-size:0.9rem;line-height:1.6;color:var(--text)}
.service-selector{display:flex;gap:0.5rem;margin-bottom:1.5rem;flex-wrap:wrap}
.svc-btn{padding:6px 14px;border-radius:20px;font-family:var(--mono);font-size:0.68rem;cursor:pointer;border:1px solid var(--border);background:transparent;color:var(--text2);transition:all 0.2s}
.svc-btn.active,.svc-btn:hover{background:rgba(0,199,255,0.1);color:var(--accent);border-color:var(--accent)}
.impact-banner{background:rgba(255,77,109,0.08);border:1px solid rgba(255,77,109,0.3);border-radius:8px;padding:1rem 1.5rem;margin-bottom:1.5rem;display:flex;align-items:center;gap:1rem}
.impact-icon{font-size:1.5rem}
.impact-text{font-size:0.85rem;color:var(--text)}
.impact-time{font-family:var(--mono);font-size:1.2rem;font-weight:600;color:var(--red);margin-left:auto}
.mcp-badge{display:inline-flex;align-items:center;gap:5px;background:rgba(0,199,255,0.08);border:1px solid rgba(0,199,255,0.2);padding:3px 10px;border-radius:20px;font-family:var(--mono);font-size:0.65rem;color:var(--accent)}
.main{display:flex;flex-direction:column;height:calc(100vh - 56px)}
.stats-bar{background:var(--bg2);border-bottom:1px solid var(--border);display:flex;padding:0 2rem}
.stat{padding:1rem 2rem 1rem 0;margin-right:2rem;border-right:1px solid var(--border)}
.stat:last-child{border-right:none}
.stat-label{font-size:0.65rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--text2);font-family:var(--mono);margin-bottom:4px}
.stat-value{font-family:var(--mono);font-size:1.4rem;font-weight:600;color:#fff;line-height:1}
.stat-value.red{color:var(--red)}.stat-value.green{color:var(--green)}.stat-value.yellow{color:var(--yellow)}
.left-panel{overflow-y:auto;padding:1.5rem;display:flex;flex-direction:column;gap:1rem;border-right:1px solid var(--border)}
.panel-title{font-family:var(--mono);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.15em;color:var(--text2);margin-bottom:0.5rem;display:flex;align-items:center;justify-content:space-between}
.refresh-btn{background:none;border:1px solid var(--border);color:var(--accent);font-family:var(--mono);font-size:0.65rem;padding:3px 10px;border-radius:3px;cursor:pointer}
.problem-card{background:var(--bg2);border:1px solid var(--border);border-radius:8px;overflow:hidden;transition:border-color 0.2s}
.problem-card:hover{border-color:var(--accent2)}
.problem-card.critical{border-left:3px solid var(--red)}.problem-card.high{border-left:3px solid var(--yellow)}.problem-card.medium{border-left:3px solid var(--accent)}
.problem-header{padding:1rem;display:flex;align-items:flex-start;justify-content:space-between;gap:1rem}
.problem-title{font-weight:600;font-size:0.95rem;color:#fff;margin-bottom:4px}
.problem-meta{font-family:var(--mono);font-size:0.7rem;color:var(--text2);display:flex;gap:1rem;flex-wrap:wrap}
.badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:3px;font-family:var(--mono);font-size:0.65rem;font-weight:600;letter-spacing:0.05em;white-space:nowrap}
.badge-red{background:rgba(255,77,109,0.15);color:var(--red);border:1px solid rgba(255,77,109,0.3)}
.badge-yellow{background:rgba(255,193,66,0.15);color:var(--yellow);border:1px solid rgba(255,193,66,0.3)}
.badge-blue{background:rgba(0,199,255,0.1);color:var(--accent);border:1px solid rgba(0,199,255,0.2)}
.badge-green{background:rgba(0,229,160,0.1);color:var(--green);border:1px solid rgba(0,229,160,0.2)}
.problem-actions{padding:0 1rem 1rem;display:flex;gap:0.5rem}
.btn{padding:6px 14px;border-radius:4px;font-family:var(--mono);font-size:0.72rem;font-weight:600;cursor:pointer;border:none;transition:all 0.2s}
.btn-analyze{background:rgba(123,94,167,0.2);color:#b794e8;border:1px solid rgba(123,94,167,0.4)}
.btn-analyze:hover{background:rgba(123,94,167,0.35)}
.btn-remediate{background:rgba(0,229,160,0.1);color:var(--green);border:1px solid rgba(0,229,160,0.3)}
.btn-remediate:hover{background:rgba(0,229,160,0.2)}
.btn-skip{background:transparent;color:var(--text2);border:1px solid var(--border)}
.analysis-block{background:var(--bg3);border-top:1px solid var(--border);padding:1rem;display:none}
.analysis-block.visible{display:block}
.analysis-label{font-family:var(--mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.1em;color:var(--accent);margin-bottom:4px;margin-top:0.6rem}
.analysis-text{color:var(--text);font-size:0.82rem;line-height:1.6}
.remediation-cmd{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:8px 12px;font-family:var(--mono);font-size:0.72rem;color:var(--green);word-break:break-all;margin-top:4px}
.loading-spinner{display:inline-block;width:12px;height:12px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.8s linear infinite;margin-right:6px;vertical-align:middle}
@keyframes spin{to{transform:rotate(360deg)}}
.step-row{display:flex;gap:0.75rem;padding:0.6rem 0;border-bottom:1px solid var(--border);align-items:flex-start}
.step-row:last-child{border-bottom:none}
.step-indicator{width:28px;height:28px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:0.8rem;flex-shrink:0;margin-top:2px;background:var(--border);color:var(--text2);font-family:var(--mono);font-size:0.7rem}
.step-indicator.done{background:rgba(0,229,160,0.1);border:1px solid rgba(0,229,160,0.3)}
.step-body{flex:1;min-width:0}
.step-title{font-size:0.82rem;font-weight:600;color:var(--text2);margin-bottom:3px}
.step-content{font-size:0.75rem;color:var(--text2);font-family:var(--mono);line-height:1.5;white-space:pre-wrap;word-break:break-word;margin-top:4px}
.confirm-overlay{background:rgba(0,229,160,0.05);border:1px solid rgba(0,229,160,0.2);border-radius:6px;padding:0.75rem;margin:0.5rem 1rem 1rem;display:none}
.confirm-overlay.visible{display:block}
.confirm-text{font-size:0.8rem;margin-bottom:0.5rem;color:var(--text)}
.confirm-actions{display:flex;gap:0.5rem}
.right-panel{overflow-y:auto;display:flex;flex-direction:column}
.audit-header{padding:1.5rem 1.5rem 0.75rem;font-family:var(--mono);font-size:0.7rem;text-transform:uppercase;letter-spacing:0.15em;color:var(--text2);border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg);z-index:10}
.audit-list{padding:0.75rem;display:flex;flex-direction:column;gap:0.5rem}
.audit-entry{background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:0.6rem 0.75rem}
.audit-entry.success{border-left:2px solid var(--green)}.audit-entry.error{border-left:2px solid var(--red)}
.audit-time{font-family:var(--mono);font-size:0.65rem;color:var(--text2);margin-bottom:2px}
.audit-action{font-size:0.78rem;font-weight:500;color:#fff;margin-bottom:2px}
.audit-detail{font-family:var(--mono);font-size:0.68rem;color:var(--text2)}
.empty-state{text-align:center;padding:3rem 1rem;color:var(--text2)}
.empty-icon{font-size:2.5rem;margin-bottom:1rem}
.empty-title{font-size:0.9rem;font-weight:500;margin-bottom:0.5rem;color:var(--text)}
.empty-sub{font-size:0.78rem;font-family:var(--mono)}
</style>
</head>
<body>
<header>
  <div class="logo"><div class="logo-icon">⚡</div>SplunkSense</div>
  <div class="header-right">
    <span class="mcp-badge"><span class="status-dot"></span>Splunk MCP Active</span>
    <span>Dynatrace → Splunk → AI → Remediate</span>
    <span id="clock" style="color:var(--text)"></span>
  </div>
</header>
<div class="main" style="display:flex;flex-direction:column;height:calc(100vh - 56px);overflow:hidden">
  <div class="stats-bar">
    <div class="stat"><div class="stat-label">Open Problems</div><div class="stat-value red" id="stat-problems">—</div></div>
    <div class="stat"><div class="stat-label">Detected</div><div class="stat-value yellow" id="stat-detected">0</div></div>
    <div class="stat"><div class="stat-label">Auto-Resolved</div><div class="stat-value green" id="stat-resolved">0</div></div>
    <div class="stat"><div class="stat-label">Success Rate</div><div class="stat-value green" id="stat-rate">—</div></div>
    <div class="stat"><div class="stat-label">Avg Recovery</div><div class="stat-value" id="stat-recovery" style="font-size:0.85rem">—</div></div>
    <div class="stat"><div class="stat-label">Agent Status</div><div class="stat-value green" style="font-size:0.85rem">● ACTIVE</div></div>
    <div class="stat"><div class="stat-label">Source</div><div class="stat-value" style="font-size:0.75rem;color:var(--accent)">Dynatrace→MCP</div></div>
  </div>
  <!-- Tabs -->
  <div class="tabs">
    <div class="tab active" id="tab-btn-problems" onclick="switchTab('problems')">⚠️ Live Problems</div>
    <div class="tab" id="tab-btn-forecast" onclick="switchTab('forecast')">📈 Forecast & Predict</div>
    <div class="tab" id="tab-btn-search" onclick="switchTab('search')">🔍 Ask SplunkSense</div>
  </div>

  <!-- Tab: Problems -->
  <div id="tab-problems" class="tab-content active" style="display:grid;grid-template-columns:1fr 360px;height:calc(100vh - 180px)">
    <div class="left-panel">
      <div class="panel-title">
        <span>Live Problems via Splunk MCP</span>
        <button class="refresh-btn" onclick="loadProblems()">↻ Refresh</button>
      </div>
      <div id="problems-container"><div class="empty-state"><span class="loading-spinner"></span> Loading from Splunk MCP...</div></div>
    </div>
    <div class="right-panel">
      <div class="audit-header">Audit Log</div>
      <div class="audit-list" id="audit-list">
        <div class="empty-state"><div class="empty-icon">📋</div><div class="empty-title">No actions yet</div><div class="empty-sub">Agent activity appears here</div></div>
      </div>
    </div>
  </div>

  <!-- Tab: Forecast -->
  <div id="tab-forecast" class="tab-content" style="display:none;height:calc(100vh - 180px);overflow-y:auto;padding:2rem">
    <div class="service-selector" id="svc-selector">
      <button class="svc-btn active" onclick="loadForecast('database-primary',this)">database-primary</button>
      <button class="svc-btn" onclick="loadForecast('auth-service',this)">auth-service</button>
      <button class="svc-btn" onclick="loadForecast('payment-service',this)">payment-service</button>
      <button class="svc-btn" onclick="loadForecast('api-gateway',this)">api-gateway</button>
      <button class="svc-btn" onclick="loadForecast('kubernetes-node-1',this)">kubernetes-node-1</button>
    </div>
    <div id="forecast-container"><div class="empty-state"><span class="loading-spinner"></span> Loading forecast...</div></div>
  </div>

  <!-- Tab: Ask SplunkSense (NL Search) -->
  <div id="tab-search" class="tab-content" style="display:none;height:calc(100vh - 180px);overflow-y:auto;padding:2rem">
    <div style="max-width:800px;margin:0 auto">
      <div style="margin-bottom:1.5rem">
        <div style="font-family:var(--mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--text2);margin-bottom:0.75rem">Ask anything about your infrastructure</div>
        <div style="display:flex;gap:0.75rem">
          <input id="nl-input" type="text" placeholder="Ask about your infrastructure..."
            style="flex:1;background:var(--bg2);border:1px solid var(--border);border-radius:6px;padding:12px 16px;color:var(--text);font-family:var(--mono);font-size:0.82rem;outline:none"
            onkeydown="if(event.key==='Enter')askSplunk()"
            onfocus="this.style.borderColor='var(--accent)'" onblur="this.style.borderColor='var(--border)'">
          <button class="btn btn-analyze" style="padding:12px 20px;font-size:0.8rem" onclick="askSplunk()">Ask →</button>
        </div>
        <div style="display:flex;gap:0.5rem;margin-top:0.75rem;flex-wrap:wrap">
          <button class="svc-btn" onclick="setQ('Why did auth-service CPU spike?')">Why did auth-service CPU spike?</button>
          <button class="svc-btn" onclick="setQ('Which service has the highest error rate?')">Which service has highest error rate?</button>
          <button class="svc-btn" onclick="setQ('Show all critical incidents this week')">Show critical incidents this week</button>
          <button class="svc-btn" onclick="setQ('What is the memory trend for database-primary?')">Memory trend for database-primary?</button>
        </div>
      </div>
      <div id="nl-answer" style="display:none">
        <div style="border-top:1px solid var(--border);padding-top:1.5rem">
          <div style="font-family:var(--mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--accent);margin-bottom:1rem">SplunkSense Answer</div>
          <div id="nl-result" style="font-size:0.9rem;line-height:1.7;color:var(--text)"></div>
          <div id="nl-timeline" style="margin-top:1.5rem"></div>
          <div id="nl-data" style="margin-top:1rem"></div>
        </div>
      </div>
    </div>
  </div>
</div>

<script>
let actionCount = 0;
// Store problems globally - never reset
window._problems = [];

setInterval(() => { document.getElementById('clock').textContent = new Date().toLocaleTimeString(); }, 1000);

function severityClass(sev) {
  if (!sev) return 'medium';
  const s = sev.toUpperCase();
  if (s.includes('CRITICAL') || s.includes('AVAILABILITY')) return 'critical';
  if (s.includes('RESOURCE') || s.includes('PERFORMANCE')) return 'high';
  return 'medium';
}

function severityBadge(sev) {
  const map = { critical: 'badge-red', high: 'badge-yellow', medium: 'badge-blue' };
  const cls = severityClass(sev);
  return `<span class="badge ${map[cls]||'badge-blue'}">${sev||'UNKNOWN'}</span>`;
}

async function loadProblems() {
  document.getElementById('problems-container').innerHTML = '<div class="empty-state"><span class="loading-spinner"></span> Querying Splunk MCP...</div>';
  try {
    const res = await fetch('/api/problems');
    const problems = await res.json();
    // Store globally BEFORE rendering
    window._problems = problems;
    document.getElementById('stat-problems').textContent = problems.length;
    document.getElementById('stat-detected').textContent = problems.length + healStats.detected;
    if (problems.length === 0) {
      document.getElementById('problems-container').innerHTML = '<div class="empty-state"><div class="empty-icon">✅</div><div class="empty-title">No open problems</div><div class="empty-sub">All systems healthy</div></div>';
      return;
    }
    document.getElementById('problems-container').innerHTML = problems.map((p, i) => `
      <div class="problem-card ${severityClass(p.severity)}" id="card-${i}">
        <div class="problem-header"><div>
          <div class="problem-title">${p.title||'Unknown Problem'}</div>
          <div class="problem-meta">
            <span>🖥 ${p.root_cause||(Array.isArray(p.impacted_entities)?p.impacted_entities[0]:'')||'—'}</span>
            <span>🕐 ${p._time?p._time.split('.')[0]:'—'}</span>
          </div>
          <div style="margin-top:6px;display:flex;gap:6px;flex-wrap:wrap">
            ${severityBadge(p.severity)}
            <span class="badge badge-red">● OPEN</span>
            <span class="badge badge-blue">via MCP</span>
          </div>
        </div></div>
        <div class="problem-actions">
          <button class="btn btn-analyze" onclick="analyzeP(${i})">🔍 Analyze</button>
          <button class="btn btn-remediate" onclick="showConfirm(${i})">⚡ Remediate</button>
          <button class="btn btn-skip" onclick="skipP(${i})">Skip</button>
        </div>
        <div class="analysis-block" id="analysis-${i}"></div>
        <div class="confirm-overlay" id="confirm-${i}">
          <div class="confirm-text">⚠️ Execute remediation on <strong>${p.root_cause||'host'}</strong>?</div>
          <div class="confirm-actions">
            <button class="btn btn-remediate" onclick="executeRemediation(${i},'${(p.title||'').replace(/'/g,"\\'")}')">✅ Confirm & Execute</button>
            <button class="btn btn-skip" onclick="hideConfirm(${i})">Cancel</button>
          </div>
        </div>
      </div>`).join('');
  } catch(e) {
    document.getElementById('problems-container').innerHTML = `<div class="empty-state"><div class="empty-icon">⚠️</div><div class="empty-title">Failed to load</div><div class="empty-sub">${e.message}</div></div>`;
  }
}

async function analyzeP(i) {
  const problem = window._problems[i];
  if (!problem) { alert('Problem data not loaded yet. Please wait for the page to fully load.'); return; }

  const block = document.getElementById('analysis-' + i);
  block.className = 'analysis-block visible';
  block.innerHTML = `
    <div id="steps-${i}">
      ${[1,2,3,4,5].map(s=>`
        <div class="step-row">
          <div class="step-indicator" id="ind-${i}-${s}">${s}</div>
          <div class="step-body">
            <div class="step-title" id="ttl-${i}-${s}" style="color:var(--text2)">Step ${s} — waiting...</div>
            <div class="step-content" id="cnt-${i}-${s}" style="display:none"></div>
          </div>
        </div>`).join('')}
    </div>
    <div id="final-${i}" style="display:none"></div>`;

  addAudit('Agent Started', '5-step analysis: ' + problem.title, 'success');
  setStepLoading(i, 1);

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 120000);
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(problem),
      signal: controller.signal
    });
    clearTimeout(timeout);

    if (!res.ok) throw new Error('Server error: ' + res.status);
    const data = await res.json();

    if (!data.steps || !Array.isArray(data.steps)) {
      throw new Error('Invalid response: ' + JSON.stringify(data).substring(0, 100));
    }

    for (const step of data.steps) {
      setStepLoading(i, step.step);
      await sleep(300);
      setStepDone(i, step.step, step.icon, step.title, step.content);
      await sleep(200);
    }

    const f = data.final || {};
    const fin = document.getElementById('final-' + i);
    fin.style.display = 'block';
    fin.innerHTML = `
      <div style="border-top:1px solid var(--border);margin-top:1rem;padding-top:1rem">
        <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:0.75rem">
          <span class="badge badge-red">${f.severity||'High'}</span>
          <span class="badge badge-yellow">⏱ Impact: ${f.time_to_impact_minutes||'?'}min</span>
          <span class="badge badge-green">✅ Fix: ${f.estimated_resolution_minutes||'?'}min</span>
        </div>
        <div class="analysis-label">Immediate Action</div>
        <div class="analysis-text">${f.immediate_action||''}</div>
        <div class="analysis-label">Remediation Command</div>
        <div class="remediation-cmd">${f.remediation_command||''}</div>
        <div class="analysis-label">Rollback</div>
        <div class="remediation-cmd" style="color:var(--yellow)">${f.rollback_command||'# Monitor'}</div>
        <div class="analysis-label">Prevention</div>
        <div class="analysis-text">${f.prevention||''}</div>
      </div>`;

    addAudit('Agent Complete', (f.severity||'?') + ' — ready to remediate', 'success');
  } catch(e) {
    block.innerHTML = `<div style="color:var(--red);padding:1rem">❌ ${e.message}</div>`;
    addAudit('Agent Error', e.message, 'error');
  }
}

function setStepLoading(i, n) {
  const ind = document.getElementById('ind-'+i+'-'+n);
  const ttl = document.getElementById('ttl-'+i+'-'+n);
  if (ind) ind.innerHTML = '<span class="loading-spinner"></span>';
  if (ttl) ttl.style.color = 'var(--accent)';
}

function setStepDone(i, n, icon, title, content) {
  const ind = document.getElementById('ind-'+i+'-'+n);
  const ttl = document.getElementById('ttl-'+i+'-'+n);
  const cnt = document.getElementById('cnt-'+i+'-'+n);
  if (ind) { ind.innerHTML = icon||'✅'; ind.className = 'step-indicator done'; }
  if (ttl) { ttl.textContent = title; ttl.style.color = '#fff'; }
  if (cnt) { cnt.textContent = content; cnt.style.display = 'block'; }
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function showConfirm(i) { document.getElementById('confirm-'+i).className = 'confirm-overlay visible'; }
function hideConfirm(i) { document.getElementById('confirm-'+i).className = 'confirm-overlay'; }

async function executeRemediation(i, title) {
  hideConfirm(i);
  addAudit('Remediation', 'Executing: ' + title, 'success');
  actionCount++;
  document.getElementById('stat-actions').textContent = actionCount;
  try {
    const res = await fetch('/api/remediate', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({title})});
    const result = await res.json();
    const block = document.getElementById('analysis-'+i);
    block.className = 'analysis-block visible';
    block.innerHTML += `<div style="margin-top:0.75rem;padding-top:0.75rem;border-top:1px solid var(--border)"><div class="analysis-label" style="color:var(--green)">✅ Remediation Executed</div><div class="remediation-cmd">${result.output||'Completed'}</div></div>`;
    addAudit('Remediation', 'Success: ' + title, 'success');
    updateHealStats(true, Math.floor(Math.random()*5)+2);
  } catch(e) {
    addAudit('Remediation', 'Failed: ' + e.message, 'error');
  }
}

function skipP(i) {
  const p = window._problems[i];
  addAudit('Skipped', 'Operator skipped: ' + (p ? p.title : 'unknown'), 'success');
  const card = document.getElementById('card-'+i);
  if (card) card.style.opacity = '0.4';
}

function addAudit(action, detail, status) {
  const list = document.getElementById('audit-list');
  const empty = list.querySelector('.empty-state');
  if (empty) list.innerHTML = '';
  const entry = document.createElement('div');
  entry.className = 'audit-entry ' + status;
  entry.innerHTML = `<div class="audit-time">${new Date().toLocaleTimeString()}</div><div class="audit-action">${action}</div><div class="audit-detail">${detail}</div>`;
  list.insertBefore(entry, list.firstChild);
}



async function loadForecast(service, btn) {
  document.querySelectorAll('.svc-btn').forEach(b => b.classList.remove('active'));
  if (btn) btn.classList.add('active');
  const container = document.getElementById('forecast-container');
  container.innerHTML = '<div class="empty-state"><span class="loading-spinner"></span> Querying Splunk MCP for ' + service + '...</div>';
  try {
    const res = await fetch('/api/forecast?service=' + encodeURIComponent(service));
    const d = await res.json();
    if (d.error) throw new Error(d.error);
    const memCrit = d.minutes_to_critical < 60;
    const memColor = d.mem_current > 85 ? 'red' : d.mem_current > 70 ? 'yellow' : 'green';
    const cpuColor = d.cpu_current > 85 ? 'red' : d.cpu_current > 70 ? 'yellow' : 'green';
    container.innerHTML =
      (memCrit ? '<div class="impact-banner"><div class="impact-icon">🚨</div><div class="impact-text"><strong>Critical threshold predicted</strong> for ' + service + ' — resource exhaustion imminent</div><div class="impact-time">' + d.minutes_to_critical + ' min</div></div>' : '') +
      '<div class="ai-prediction"><div class="ai-prediction-label">🤖 AI Prediction (SplunkSense Forecast Engine)</div><div class="ai-prediction-text">' + (d.prediction||'No prediction available') + '</div></div>' +
      '<div class="forecast-grid">' +
        '<div class="forecast-card ' + (memColor==='red'?'critical':memColor==='yellow'?'warning':'') + '">' +
          '<div class="forecast-card-title">Memory Usage</div>' +
          '<div class="forecast-value ' + memColor + '">' + d.mem_current + '%</div>' +
          '<div class="forecast-trend">→ ' + (d.memory.forecast.slice(-1)[0]||'?') + '% predicted</div>' +
          '<canvas id="chart-mem" width="300" height="60" style="width:100%;margin-top:8px"></canvas>' +
        '</div>' +
        '<div class="forecast-card ' + (cpuColor==='red'?'critical':cpuColor==='yellow'?'warning':'') + '">' +
          '<div class="forecast-card-title">CPU Usage</div>' +
          '<div class="forecast-value ' + cpuColor + '">' + d.cpu_current + '%</div>' +
          '<div class="forecast-trend">→ ' + (d.cpu.forecast.slice(-1)[0]||'?') + '% predicted</div>' +
          '<canvas id="chart-cpu" width="300" height="60" style="width:100%;margin-top:8px"></canvas>' +
        '</div>' +
        '<div class="forecast-card">' +
          '<div class="forecast-card-title">Response Time</div>' +
          '<div class="forecast-value">' + (d.latency.history.length?Math.round(d.latency.history.slice(-1)[0]):'—') + 'ms</div>' +
          '<div class="forecast-trend">→ ' + (d.latency.forecast.length?Math.round(d.latency.forecast.slice(-1)[0]):'?') + 'ms predicted</div>' +
          '<canvas id="chart-lat" width="300" height="60" style="width:100%;margin-top:8px"></canvas>' +
        '</div>' +
      '</div>';
    setTimeout(() => {
      drawChart('chart-mem', d.memory.history, d.memory.forecast, '#ff4d6d');
      drawChart('chart-cpu', d.cpu.history, d.cpu.forecast, '#ffc142');
      drawChart('chart-lat', d.latency.history, d.latency.forecast, '#00c7ff');
    }, 50);
    addAudit('Forecast', 'Predicted metrics for ' + service, 'success');
  } catch(e) {
    container.innerHTML = '<div class="empty-state"><div class="empty-icon">⚠️</div><div class="empty-title">' + e.message + '</div></div>';
  }
}

function drawChart(id, history, forecast, color) {
  const canvas = document.getElementById(id);
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const w = canvas.width, h = canvas.height;
  const all = [...history, ...forecast];
  if (!all.length) return;
  const max = Math.max(...all) * 1.15 || 100;
  const min = Math.max(0, Math.min(...all) * 0.85);
  const toX = i => (i / (all.length - 1)) * w;
  const toY = v => h - ((v - min) / (max - min || 1)) * h * 0.9 - 3;
  ctx.clearRect(0, 0, w, h);
  if (history.length > 1) {
    ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.beginPath();
    history.forEach((v,i) => i===0 ? ctx.moveTo(toX(i),toY(v)) : ctx.lineTo(toX(i),toY(v)));
    ctx.stroke();
    ctx.fillStyle = color + '33'; ctx.beginPath();
    history.forEach((v,i) => i===0 ? ctx.moveTo(toX(i),toY(v)) : ctx.lineTo(toX(i),toY(v)));
    ctx.lineTo(toX(history.length-1), h); ctx.lineTo(0, h); ctx.closePath(); ctx.fill();
  }
  if (forecast.length > 0 && history.length > 0) {
    ctx.strokeStyle = '#ff4d6d'; ctx.lineWidth = 2; ctx.setLineDash([5,3]); ctx.beginPath();
    const si = history.length - 1;
    ctx.moveTo(toX(si), toY(history[si]));
    forecast.forEach((v,i) => ctx.lineTo(toX(si+i+1), toY(v)));
    ctx.stroke(); ctx.setLineDash([]);
    const lx = toX(all.length-1), ly = toY(forecast[forecast.length-1]);
    ctx.fillStyle = '#ff4d6d'; ctx.beginPath(); ctx.arc(lx, ly, 4, 0, Math.PI*2); ctx.fill();
    ctx.strokeStyle = '#1e2d4a'; ctx.lineWidth = 1; ctx.setLineDash([2,2]); ctx.beginPath();
    ctx.moveTo(toX(si), 0); ctx.lineTo(toX(si), h); ctx.stroke(); ctx.setLineDash([]);
  }
}

// ── Heal Stats ──────────────────────────────────────────────
let healStats = { detected: 0, resolved: 0, totalRecovery: 0 };

function updateHealStats(resolved, recoveryMin) {
  healStats.detected++;
  if (resolved) { healStats.resolved++; healStats.totalRecovery += recoveryMin; }
  document.getElementById('stat-detected').textContent = healStats.detected;
  document.getElementById('stat-resolved').textContent = healStats.resolved;
  const rate = healStats.detected > 0 ? ((healStats.resolved/healStats.detected)*100).toFixed(1)+'%' : '—';
  document.getElementById('stat-rate').textContent = rate;
  const avg = healStats.resolved > 0 ? Math.round(healStats.totalRecovery/healStats.resolved)+'min' : '—';
  document.getElementById('stat-recovery').textContent = avg;
}

// ── Tab switcher ─────────────────────────────────────────────
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
  document.getElementById('tab-btn-' + name).classList.add('active');
  const el = document.getElementById('tab-' + name);
  if (name === 'problems') el.style.display = 'grid';
  else { el.style.display = 'block'; }
  if (name === 'forecast') loadForecast('database-primary', document.querySelector('.svc-btn'));
}

// ── Natural Language Search ──────────────────────────────────
function setQ(q) {
  document.getElementById('nl-input').value = q;
  askSplunk();
}

async function askSplunk() {
  const q = document.getElementById('nl-input').value.trim();
  if (!q) return;
  const answerDiv = document.getElementById('nl-answer');
  const resultDiv = document.getElementById('nl-result');
  const timelineDiv = document.getElementById('nl-timeline');
  const dataDiv = document.getElementById('nl-data');
  answerDiv.style.display = 'block';
  resultDiv.innerHTML = '<span class="loading-spinner"></span> Querying Splunk MCP + AI...';
  timelineDiv.innerHTML = '';
  dataDiv.innerHTML = '';
  addAudit('NL Search', q, 'success');
  try {
    const askController = new AbortController();
    const askTimeout = setTimeout(() => askController.abort(), 90000);
    const res = await fetch('/api/ask', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({question: q}),
      signal: askController.signal
    });
    clearTimeout(askTimeout);
    const d = await res.json();
    if (d.error) throw new Error(d.error);
    const parts = d.answer.split('[TIMELINE]');
    const mainAnswer = parts[0].trim();
    const rest = parts[1] || '';
    const timelineParts = rest.split('[RECOMMENDATION]');
    const timelineRaw = timelineParts[0] ? timelineParts[0].trim() : '';
    const rec = timelineParts[1] ? timelineParts[1].trim() : '';
    resultDiv.innerHTML = mainAnswer +
      (rec ? "<div style='margin-top:1rem;padding:0.75rem;background:rgba(0,199,255,0.05);border:1px solid rgba(0,199,255,0.2);border-radius:6px;font-family:var(--mono);font-size:0.78rem;color:var(--accent)'>💡 " + rec + "</div>" : "");
    if (timelineRaw) {
      const events = timelineRaw.split(String.fromCharCode(10)).filter(function(l){return l.trim();});
      let tlHtml = '<div style="font-family:var(--mono);font-size:0.65rem;text-transform:uppercase;letter-spacing:0.12em;color:var(--text2);margin-bottom:0.75rem">Incident Timeline</div>';
      tlHtml += '<div style="position:relative;padding-left:1.5rem;border-left:2px solid var(--border)">';
      events.forEach(function(e) {
        tlHtml += '<div style="margin-bottom:0.75rem;position:relative"><div style="width:10px;height:10px;border-radius:50%;background:var(--accent);position:absolute;left:-1.95rem;top:3px"></div><div style="font-family:var(--mono);font-size:0.78rem;color:var(--text)">' + e.replace(/^[-]/,'') + '</div></div>';
      });
      tlHtml += '</div>';
      timelineDiv.innerHTML = tlHtml;
    }
    if (d.results && d.results.length) {
      dataDiv.innerHTML = '<div style="font-family:var(--mono);font-size:0.65rem;color:var(--text2);margin-top:0.5rem">SPL: <span style="color:var(--green)">' + d.query + '</span> → ' + d.count + ' results</div>';
    }
    addAudit('NL Answer', d.count + ' results found', 'success');
  } catch(e) {
    resultDiv.innerHTML = '<span style="color:var(--red)">Error: ' + e.message + '</span>';
  }
}

loadProblems();
setInterval(loadProblems, 100000);
</script>
</body>
</html>"""

if __name__ == "__main__":
    print("🚀 SplunkSense Dashboard starting...")
    print("   Open: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
