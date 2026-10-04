import json
import io, urllib.error
from app.supporting import enrich, navigator, sigma_export, parse_zeek, parse_windows_json, ecs, redact
from app.detector import analyze, _norm
from app.generator import generate
from fastapi.testclient import TestClient
from app.main import app
import app.main as main_module

def fixture():
    events,labels=generate(); res,evs=analyze([_norm(x) for x in events],labels); return enrich(res,evs),evs

def test_funnel_heatmap_and_counterfactuals():
    r,_=fixture(); assert r["funnel"]["events"]>r["funnel"]["alerts"]>0
    assert r["attack_heatmap"] and r["counterfactuals"]

def test_navigator_sigma_and_priority_playbooks():
    r,_=fixture(); assert navigator(r)["techniques"] and "title:" in sigma_export(r)
    assert all(i["priority_score"]>=0 and i["executive_summary"] and i["playbook"] for i in r["incidents"])

def test_honeytokens_peer_baselines_and_enrichment_caveat():
    r,evs=fixture(); account=next(e["user"] for e in evs if e["user"]); enriched=enrich(r,evs,honeytokens=[account]); assert enriched["honeytoken_hits"]
    assert enriched["peer_baselines"] and "no lookup" in enriched["enrichment_status"]["geoip"]

def test_zeek_windows_parsers_and_ecs_redaction():
    z="#separator \\t\n#fields\tts\tid.orig_h\tid.resp_h\torig_bytes\n1791000000\t1.2.3.4\t10.0.0.1\t42\n"
    rows=parse_zeek(z); assert rows[0]["ip"]=="1.2.3.4"
    w=json.dumps({"Events":[{"System":{"EventID":4625,"TimeCreated":{"SystemTime":"2026-10-03T01:00:00Z"},"Computer":"host"}}]})
    assert parse_windows_json(w)[0]["outcome"]=="fail"
    r,evs=fixture(); data=ecs(r,evs); safe=redact(data); assert len(safe["events"])==len(evs)

def test_new_api_exports_parsers_and_comparison():
    client=TestClient(app)
    first=client.get("/api/demo").json()["run_id"]
    assert client.get("/api/export/navigator").status_code==200
    assert "title:" in client.get("/api/sigma").text
    assert client.get("/api/export/ecs?redact_pii=true").json()["events"]
    second=client.get("/api/demo").json()["run_id"]
    assert client.get(f"/api/compare/{first}/{second}").json()["summary"]["events_delta"]==0
    imported=client.post("/api/sigma/import",files={"file":("rule.yml",b"title: Example\nid: test-rule\n")}).json()
    assert imported["count"]==1 and imported["rules"][0]["id"]=="test-rule"
    zeek="#separator \\t\n#fields\tts\tid.orig_h\tid.resp_h\torig_bytes\n1791000000\t1.2.3.4\t10.0.0.1\t42\n"
    assert client.post("/api/parse/zeek",files={"file":("conn.log",zeek)}).json()["count"]==1
    windows=json.dumps({"Events":[{"System":{"EventID":4625,"TimeCreated":{"SystemTime":"2026-10-03T01:00:00Z"}}}]})
    assert client.post("/api/parse/windows",files={"file":("event.json",windows)}).json()["count"]==1

def test_dashboard_brand_and_offline_chat(monkeypatch):
    monkeypatch.delenv("HINDSIGHT_LLM_API_KEY",raising=False)
    client=TestClient(app)
    page=client.get("/").text
    assert 'id="sidebarToggle"' in page and 'id="chatWidget"' in page and 'src="/logo.png"' in page and 'brand-caption">Hindsight IDS' in page
    assert client.get("/logo.png").headers["content-type"].startswith("image/png")
    client.get("/api/demo")
    chat=client.post("/api/chat",json={"question":"What should I investigate first?"}).json()
    assert chat["provider"]=="offline guidance" and "incident" in chat["answer"].lower()
    summary=client.post("/api/chat",json={"question":"Summarize this run"}).json()
    explain=client.post("/api/chat",json={"question":"Explain the detections"}).json()
    assert "Run summary" in summary["answer"] and "evidence" in explain["answer"].lower()
    assert len({chat["answer"],summary["answer"],explain["answer"]})==3

def test_invalid_llm_key_falls_back_for_quick_prompts(monkeypatch):
    monkeypatch.setenv("HINDSIGHT_LLM_API_KEY","invalid-test-key")
    def unauthorized(*args,**kwargs):
        raise urllib.error.HTTPError("https://example.invalid",401,"Unauthorized",{},io.BytesIO(b"unauthorized"))
    monkeypatch.setattr(main_module.urllib.request,"urlopen",unauthorized)
    client=TestClient(app); client.get("/api/demo")
    response=client.post("/api/chat",json={"question":"What should I investigate first?"})
    assert response.status_code==200
    payload=response.json()
    assert payload["provider"]=="offline fallback" and "HTTP 401" in payload["notice"]
    assert "incident" in payload["answer"].lower()

def test_chat_can_answer_general_questions_when_provider_is_configured(monkeypatch):
    monkeypatch.setenv("HINDSIGHT_LLM_API_KEY", "test-key")
    monkeypatch.setenv("HINDSIGHT_LLM_MODEL", "test-chat-model")
    captured={}
    class FakeResponse:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def read(self): return json.dumps({"choices":[{"message":{"content":"A concise general answer."}}]}).encode()
    def success(request,timeout):
        captured["request"]=json.loads(request.data)
        captured["authorization"]=request.get_header("Authorization")
        return FakeResponse()
    monkeypatch.setattr(main_module.urllib.request,"urlopen",success)
    client=TestClient(app)
    status=client.get("/api/chat/status").json()
    assert status["configured"] and status["model"]=="test-chat-model"
    response=client.post("/api/chat",json={"question":"Explain how rainbows form"}).json()
    assert response["answer"]=="A concise general answer." and response["provider"]=="test-chat-model"
    assert captured["authorization"]=="Bearer test-key"
    assert "general-purpose conversational assistant" in captured["request"]["messages"][0]["content"]

def test_local_ollama_chat_works_without_an_api_key(monkeypatch):
    monkeypatch.delenv("HINDSIGHT_LLM_API_KEY",raising=False)
    monkeypatch.setenv("HINDSIGHT_LLM_PROVIDER","ollama")
    monkeypatch.setenv("HINDSIGHT_LLM_URL","http://localhost:11434/v1/chat/completions")
    monkeypatch.setenv("HINDSIGHT_LLM_MODEL","llama3.2")
    seen={}
    class FakeResponse:
        def __enter__(self): return self
        def __exit__(self,*args): pass
        def read(self): return json.dumps({"choices":[{"message":{"content":"A fresh local model answer."}}]}).encode()
    def success(request,timeout):
        seen["url"]=request.full_url
        seen["authorization"]=request.get_header("Authorization")
        return FakeResponse()
    monkeypatch.setattr(main_module.urllib.request,"urlopen",success)
    client=TestClient(app)
    assert client.get("/api/chat/status").json()["provider"]=="Ollama local"
    result=client.post("/api/chat",json={"question":"Tell me something new about astronomy"}).json()
    assert result["answer"]=="A fresh local model answer."
    assert seen["url"]=="http://localhost:11434/v1/chat/completions" and seen["authorization"] is None
