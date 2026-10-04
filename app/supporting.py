"""Optional Hindsight enrichment/export helpers. External intelligence is opt-in and data-backed."""
import json, os, re, urllib.request
from collections import Counter, defaultdict

TECHNIQUES = {
    "T1110.001": ("Brute Force: Password Guessing", "credential-access"),
    "T1110.003": ("Brute Force: Password Spraying", "credential-access"),
    "T1078": ("Valid Accounts", "initial-access"), "T1068": ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1021": ("Remote Services", "lateral-movement"), "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1595": ("Active Scanning", "reconnaissance"), "T1190": ("Exploit Public-Facing Application", "initial-access"),
    "T1070": ("Indicator Removal", "defense-evasion"),
}

def enrich(res, events, honeytokens=None):
    """Attach derived, explicitly sourced analysis details without changing rule verdicts."""
    res["funnel"] = {"events": len(events), "alerts": len(res.get("alerts", [])), "incidents": len(res.get("incidents", []))}
    res["attack_heatmap"] = [{"techniqueID": t, "name": n, "tactic": tac, "count": sum(a.get("mitre") == t for a in res.get("alerts", []))} for t,(n,tac) in TECHNIQUES.items()]
    users=defaultdict(list)
    for e in events:
        if e.get("user"): users[e["user"]].append(e)
    res["peer_baselines"]=[]
    glob=Counter(e.get("ip") for es in users.values() for e in es if e.get("ip"))
    med=sorted(len(x) for x in users.values())[len(users)//2] if users else 0
    for user, rows in users.items():
        own=Counter(e.get("ip") for e in rows if e.get("ip")); my_ips=set(own)
        peer_ips={ip: glob[ip]-own[ip] for ip in my_ips}
        res["peer_baselines"].append({"user":user,"events":len(rows),"unique_ips":len(my_ips),"peer_median_events": med,"rare_ips":sorted(ip for ip in my_ips if peer_ips[ip]==0)})
    tokens=set(honeytokens or filter(None,os.getenv("HONEYTOKEN_ACCOUNTS","").split(",")))
    res["honeytoken_hits"]=[{"user":e.get("user"),"ip":e.get("ip"),"ts":e.get("ts"),"source":"configured account match"} for e in events if e.get("user") in tokens]
    try: geo_map=json.loads(os.getenv("HINDSIGHT_GEOIP_MAP_JSON","{}"))
    except json.JSONDecodeError: geo_map={}
    try: intel=json.loads(os.getenv("HINDSIGHT_THREAT_FEED_JSON","[]"))
    except json.JSONDecodeError: intel=[]
    intel_map={str(x.get("ip")):str(x.get("label","listed in configured local feed")) for x in intel if isinstance(x,dict) and x.get("ip")} if isinstance(intel,list) else {}
    event_by_id={e.get("id"):e for e in events}
    for a in res.get("alerts",[]):
        ips={event_by_id[i].get("ip") for i in a.get("evidence",[]) if i in event_by_id}
        a["intel_matches"]=[{"ip":ip,"label":intel_map[ip],"source":"HINDSIGHT_THREAT_FEED_JSON"} for ip in sorted(ips) if ip in intel_map]
        a["geoip"]=[{"ip":ip,"country":geo_map[ip],"source":"HINDSIGHT_GEOIP_MAP_JSON"} for ip in sorted(ips) if ip in geo_map]
    # Explain detector boundaries. These are threshold scenarios, not a promise that
    # deleting one raw line alone would change a verdict (overlapping windows matter).
    th=res.get("thresholds",{}); mb=th.get("exfil_bytes",50_000_000)/1e6
    boundaries={"brute_force":f"fewer than {th.get('brute_force_per_5min',8)} failed logins from one IP within 300 seconds (adaptive threshold for this dataset)","password_spray":"fewer than 5 distinct accounts tried by one IP within 600 seconds","compromise_after_failures":"fewer than 5 preceding failures from the same IP within 900 seconds","web_scan":f"fewer than {th.get('web_errors_per_5min',20)} HTTP 403/404 responses from one IP within 300 seconds (adaptive threshold)","web_injection":"fewer than 3 payload-matching requests from one IP within 600 seconds","lateral_movement":"fewer than 3 previously unseen hosts for a user within 900 seconds","data_exfiltration":f"no 15-minute transfer cluster reaches {mb:.0f} MB (adaptive threshold)","impossible_travel":"the two sign-ins are at least 2 hours apart","low_slow_bruteforce":"fewer than 15 failed logins from one IP within 24 hours, or they were concentrated in under 4 distinct hours","distributed_attack":"fewer than 5 distinct addresses failed against the account within one hour"}
    res["counterfactuals"]=[{"alert_id":a["id"],"rule":a["rule"],"counterfactual":f"This rule would not meet its stated boundary if {boundaries[a['rule']]}. Re-evaluate the full time window; removing one evidence row may not change overlapping detections."} for a in res.get("alerts",[]) if a.get("rule") in boundaries]
    for inc in res.get("incidents",[]):
        aa=[res["alerts"][i] for i in inc.get("alerts",[]) if i < len(res.get("alerts",[]))]
        inc["priority_score"]=sum({"critical":40,"high":25,"medium":12,"low":5}.get(a.get("severity"),0) for a in aa)
        inc["executive_summary"]=inc.get("plain",inc.get("title","Security incident"))
        inc["playbook"]=[{"action":x,"command": command_for(x)} for x in inc.get("actions",[])]
    # No inferred geo/threat claims: report unavailability unless enrichment inputs exist.
    res["enrichment_status"]={"geoip":"configured local mapping" if geo_map else "country field from source logs only; no lookup configured","threat_intel":"configured local feed" if intel_map else "no feed configured"}
    return res

def command_for(action):
    low=action.lower()
    if "address" in low or "source" in low: return "# Review and apply your organization's firewall block procedure; validate the indicator first."
    if "account" in low or "password" in low: return "# Disable/reset the affected account using your identity provider's approved admin workflow."
    return "# Follow the incident response action above; commands are intentionally not executed automatically."

def navigator(res):
    items=[]
    counts=Counter(a.get("mitre") for a in res.get("alerts",[]))
    for tid,count in counts.items():
        if tid in TECHNIQUES: items.append({"techniqueID":tid,"score":min(100,20+count*20),"comment":f"Observed in {count} alert(s); derived from this analysis."})
    return {"name":"Hindsight analysis","versions":{"attack":"15","navigator":"4.9.1","layer":"4.5"},"domain":"enterprise-attack","description":"Technique scores are based on matched Hindsight alerts.","techniques":items,"gradient":{"colors":["#fff2cc","#ff6666"],"minValue":0,"maxValue":100}}

def sigma_export(res):
    docs=[]
    for rule in sorted(set(a.get("rule") for a in res.get("alerts",[]))):
        docs.append("\n".join(["title: Hindsight observed "+rule.replace("_"," "),"id: hindsight-"+rule,"status: test","description: Exported from observed alert names; review and tune before deployment.","logsource:","  product: windows","detection:","  selection:","    HindsightRule: "+rule,"  condition: selection","level: medium"]))
    return "\n\n---\n\n".join(docs)

def parse_zeek(text):
    out=[]; lines=text.splitlines(); fields=[]
    for line in lines:
        if line.startswith("#fields"):
            fields=line.split("\t")[1:]
        elif line and not line.startswith("#") and fields:
            vals=line.split("\t"); row=dict(zip(fields,vals)); out.append({"ts":row.get("ts"),"source":"net","ip":row.get("id.orig_h",""),"host":row.get("id.resp_h",""),"user":row.get("user",""),"event":row.get("service","connection"),"outcome":row.get("conn_state",""),"detail":json.dumps(row),"bytes":int(row.get("orig_bytes",0) or 0)})
    return out

def parse_windows_json(text):
    data=json.loads(text); rows=data if isinstance(data,list) else data.get("Events",[data]) if isinstance(data,dict) else []
    out=[]
    for x in rows:
        x=x.get("Event",x); sys=x.get("System",{}); ev=sys.get("EventID",{}); ev=ev.get("#text",ev) if isinstance(ev,dict) else ev
        out.append({"ts":sys.get("TimeCreated",{}).get("SystemTime") if isinstance(sys.get("TimeCreated"),dict) else sys.get("TimeCreated"),"source":"auth","host":sys.get("Computer",""),"user":str(x.get("EventData",{}).get("Data",[{}])[0].get("#text", "") if isinstance(x.get("EventData",{}).get("Data"),list) else ""),"event":"login" if str(ev) in ("4624","4625") else "windows_event_"+str(ev),"outcome":"success" if str(ev)=="4624" else "fail" if str(ev)=="4625" else "","detail":json.dumps(x)})
    return out

def ecs(res, events):
    return {"events":[{"@timestamp":e.get("ts"),"event":{"kind":"event","category":["authentication"] if e.get("source")=="auth" else ["network"],"action":e.get("event"),"outcome":e.get("outcome")},"user":{"name":e.get("user")} if e.get("user") else {},"source":{"ip":e.get("ip")} if e.get("ip") else {},"host":{"name":e.get("host")} if e.get("host") else {},"message":e.get("detail",""),"labels":{"hindsight_event_id":e.get("id")}} for e in events],"alerts":res.get("alerts",[])}

def redact(res):
    out=json.loads(json.dumps(res))
    for key,label in (("user","USER"),("ip","IP")):
        values=set()
        def collect(obj, user_context=False):
            if isinstance(obj,dict):
                for k,v in obj.items():
                    is_user=(k=="user" or user_context or (k=="name" and obj.get("type") in ("user","account")))
                    if (k==key or (key=="user" and k=="name" and is_user)) and isinstance(v,str) and v: values.add(v)
                    collect(v,user_context or k=="user")
            elif isinstance(obj,list):
                for v in obj: collect(v,user_context)
        collect(out); mapping={v:f"{label}_{i+1}" for i,v in enumerate(sorted(values))}
        def apply(obj, user_context=False):
            if isinstance(obj,dict):
                for k,v in list(obj.items()):
                    is_user=(k=="user" or user_context or (k=="name" and obj.get("type") in ("user","account")))
                    if (k==key or (key=="user" and k=="name" and is_user)) and isinstance(v,str) and v in mapping: obj[k]=mapping[v]
                    else: apply(v,user_context or k=="user")
            elif isinstance(obj,list):
                for v in obj: apply(v,user_context)
        apply(out)
    return out

def send_webhook(payload):
    url=os.getenv("HINDSIGHT_WEBHOOK_URL","").strip()
    if not url: raise ValueError("Set HINDSIGHT_WEBHOOK_URL to enable webhook delivery.")
    kind=os.getenv("HINDSIGHT_WEBHOOK_KIND","generic").lower()
    if kind=="email":
        import smtplib
        from email.message import EmailMessage
        msg=EmailMessage(); msg["Subject"]="Hindsight IDS incident summary"; msg["From"]=os.environ["HINDSIGHT_EMAIL_FROM"]; msg["To"]=os.environ["HINDSIGHT_EMAIL_TO"]; msg.set_content(json.dumps(payload,indent=2))
        with smtplib.SMTP(os.environ["HINDSIGHT_SMTP_HOST"],int(os.getenv("HINDSIGHT_SMTP_PORT","587")),timeout=8) as server:
            server.starttls(); user=os.getenv("HINDSIGHT_SMTP_USER"); password=os.getenv("HINDSIGHT_SMTP_PASSWORD")
            if user: server.login(user,password or "")
            server.send_message(msg)
        return {"status":"sent","kind":"email"}
    message={"text":payload.get("text","Hindsight analysis complete"),"summary":payload.get("summary"),"incidents":payload.get("incidents",[])}
    body={"content":message["text"],"embeds":[{"title":"Hindsight incident summary","description":json.dumps(message,indent=2)[:4000]}]} if kind=="discord" else message
    req=urllib.request.Request(url,data=json.dumps(body).encode(),headers={"Content-Type":"application/json"},method="POST")
    with urllib.request.urlopen(req,timeout=8) as r: return {"status":r.status,"kind":kind}
