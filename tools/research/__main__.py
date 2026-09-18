"""Offline parser research command line; never executes commands from input files."""
import argparse
import json
from pathlib import Path
from .contract import read_json,canonical,compare_fields,InvalidResearch
from . import adapters,bundle,cases,minimize

def main(argv=None):
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest="cmd",required=True)
    a=sub.add_parser("audit");a.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[2])
    a=sub.add_parser("run");a.add_argument("adapter",choices=["container","product","tshark"]);a.add_argument("capture",type=Path);a.add_argument("--binary",type=Path);a.add_argument("--output",type=Path,required=True);a.add_argument("--timeout",type=float,default=30)
    a=sub.add_parser("compare");a.add_argument("left",type=Path);a.add_argument("right",type=Path)
    a=sub.add_parser("bundle");a.add_argument("capture",type=Path);a.add_argument("left",type=Path);a.add_argument("right",type=Path);a.add_argument("--specifications",type=Path,required=True);a.add_argument("--output",type=Path,required=True)
    a=sub.add_parser("verify-bundle");a.add_argument("path",type=Path)
    a=sub.add_parser("minimize");a.add_argument("capture",type=Path);a.add_argument("destination",type=Path);a.add_argument("--left",choices=["container","product","tshark"],required=True);a.add_argument("--right",choices=["container","product","tshark"],required=True);a.add_argument("--left-binary",type=Path);a.add_argument("--right-binary",type=Path);a.add_argument("--max-calls",type=int,default=40);a.add_argument("--timeout",type=float,default=30)
    a=sub.add_parser("case");a.add_argument("case_id");a.add_argument("--binary",type=Path);a.add_argument("--root",type=Path,default=Path(__file__).resolve().parents[2])
    a=p.parse_args(argv)
    if a.cmd=="audit":value=cases.audit(a.root)
    elif a.cmd=="minimize":value=minimize.reduce_adapters(a.capture,a.destination,a.left,a.right,left_binary=a.left_binary,right_binary=a.right_binary,max_calls=a.max_calls,timeout=a.timeout)
    elif a.cmd=="compare":value=compare_fields(read_json(a.left),read_json(a.right))
    elif a.cmd=="verify-bundle":value=bundle.verify(a.path)
    elif a.cmd=="bundle":value=bundle.create(a.output,a.capture,read_json(a.left),read_json(a.right),specifications=read_json(a.specifications))
    elif a.cmd=="case":case,_=cases.select(a.root,a.case_id);value=cases.run_probe_case(a.root,case,a.binary)
    else:
        if a.output.exists():raise FileExistsError(a.output)
        result=adapters.run_adapter(a.adapter,a.capture,a.binary,timeout=a.timeout)
        # Artifacts stay in a separate attributed directory, not inside a canonical observation.
        a.output.mkdir();artifacts=result.pop("artifacts",{})
        for name,raw in artifacts.items():(a.output/(name+".bin")).write_bytes(raw)
        if result.get("snapshot"):(a.output/"interpretation.json").write_bytes(canonical(result["snapshot"])+b"\n")
        (a.output/"receipt.json").write_bytes(canonical({k:v for k,v in result.items()if k!="snapshot"})+b"\n")
        value={"status":result["status"],"output":str(a.output)}
    print(json.dumps(value,indent=2))
    return 0 if value.get("status",value.get("maintenance_status","PASS"))in {"PASS","CREATED"}else 2
if __name__=="__main__":
    try:raise SystemExit(main())
    except (ValueError,OSError,KeyError)as e:print(json.dumps({"status":"ERROR","reason":str(e)}));raise SystemExit(1)
