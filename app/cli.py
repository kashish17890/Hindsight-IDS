"""Command line interface for offline Hindsight analysis."""
import argparse, json
from .detector import analyze, parse_file
from .supporting import enrich, navigator, ecs

def main():
    p=argparse.ArgumentParser(description="Analyze authentication, web, and network logs with Hindsight")
    p.add_argument("file"); p.add_argument("--format",choices=("json","ecs","navigator"),default="json"); p.add_argument("--redact-pii",action="store_true"); p.add_argument("-o","--output")
    a=p.parse_args(); events,errors=parse_file(a.file,open(a.file,"rb").read()); result,events=analyze(events); result["summary"]["parse_errors"]=errors; result=enrich(result,events)
    payload=result if a.format=="json" else ecs(result,events) if a.format=="ecs" else navigator(result)
    if a.redact_pii:
        from .supporting import redact
        payload=redact(payload)
    text=json.dumps(payload,indent=2)
    if a.output: open(a.output,"w",encoding="utf-8").write(text+"\n")
    else: print(text)
if __name__=="__main__": main()
