from pathlib import Path
import importlib.util,json,sys,time,subprocess,hashlib
from concurrent.futures import ProcessPoolExecutor,as_completed
R=Path(__file__).resolve().parents[4]
SRC=R/"artifact/code/extensions/run_searpc_twsl_pareto.py"
sys.path[:0]=[str(R/"artifact/code"/x) for x in ("participation_control","scoped_evidence","observable_selection","frozen_searpc")]
spec=importlib.util.spec_from_file_location("pareto_runner",SRC);runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
OUT=R/"outputs/final-reproduction/safety-replay"
LOG=R/"artifact/results/final_reproduction/logs"
PROTOCOL=R/"artifact/protocols/extensions/PARETO_PROTOCOL_FROZEN.md"
TRACE=R/"data/derived/rq2_trace_bundle_exact.npz"
PREDICTIONS=R/"data/derived/SEARPC_holdout_holdout_predictions.csv"
def cell(task):
 attack,overlap,seed=task
 folder=OUT/attack/"checkpoints";folder.mkdir(parents=True,exist_ok=True)
 path=folder/runner.checkpoint_name("SEARPC",attack,overlap,seed)
 protocol_hash=runner.digest(PROTOCOL)
 if runner.validate_checkpoint(path,("SEARPC",attack,overlap,seed),runner.THRESHOLDS,protocol_hash):return task
 start=time.monotonic()
 rows=runner.run_searpc_cell(R/"artifact/code/participation_control",TRACE,attack,overlap,seed,runner.THRESHOLDS)
 runner.atomic_json(path,{"method":"SEARPC","attack":attack,"overlap":overlap,"seed":seed,"elapsed_s":time.monotonic()-start,"protocol_sha256":protocol_hash,"prediction_sha256":runner.PREDICTION_SHA256,"trace_bundle_sha256":runner.TRACE_BUNDLE_SHA256,"runner_sha256":runner.digest(SRC),"rows":rows})
 return task
if __name__=="__main__":
 assert runner.digest(TRACE)==runner.TRACE_BUNDLE_SHA256
 assert runner.digest(PREDICTIONS)==runner.PREDICTION_SHA256
 started=time.time();tasks=[(a,o,s) for a in runner.ATTACKS for o in runner.OVERLAPS for s in runner.SEEDS20]
 with ProcessPoolExecutor(max_workers=8) as pool:
  for n,f in enumerate(as_completed([pool.submit(cell,x) for x in tasks]),1):print("completed",n,len(tasks),f.result(),flush=True)
 for attack in runner.ATTACKS:
  command=[sys.executable,str(SRC),"--method","SEARPC","--attack",attack,"--mode","full20","--legacy-root",str(R/"artifact/code/participation_control"),"--predictions",str(PREDICTIONS),"--trace-bundle",str(TRACE),"--raw-root",str(R/"external_data/twsl_phase13_raw"),"--protocol",str(PROTOCOL),"--output-dir",str(OUT/attack)]
  # The registered runner CLI validates completed checkpoints and writes reports.
  # A fresh serial rerun uses: python run.py safety-replay --method SEARPC --attack ATTACK --mode full20.
  with (LOG/("safety-replay-"+attack+".log")).open("w") as log:subprocess.run(command,cwd=R,stdout=log,stderr=subprocess.STDOUT,check=True)
 import pandas as pd
 frozen=pd.read_csv(R/"artifact/results/safety_coverage/pareto_raw.csv")
 comparisons=[]
 for attack in runner.ATTACKS:
  current=pd.read_csv(OUT/attack/("SEARPC_"+attack+"_full20_pareto_raw.csv"))
  reference=frozen[(frozen.method=="SEARPC")&(frozen.attack==attack)].copy()
  key=["attack","overlap","seed","threshold"]
  left=current.sort_values(key).reset_index(drop=True);right=reference.sort_values(key).reset_index(drop=True)
  assert set(left.columns)==set(right.columns)
  pd.testing.assert_frame_equal(left[right.columns],right,check_exact=True)
  comparisons.append({"attack":attack,"cells":60,"rows":len(left),"frozen_counts_and_rates_exact":True})
 runner.atomic_json(OUT/"VERIFICATION.json",{"status":"PASS","workers":8,"elapsed_s":time.time()-started,"scientific_function":"run_searpc_cell","threshold_count":91,"seeds":list(runner.SEEDS20),"comparisons":comparisons,"source_sha256":runner.digest(SRC),"parallelism":"Independent registered cells; parameters, random seeds, state updates and event traces unchanged"})
 print("FULL SEARPC threshold replay PASS",comparisons,flush=True)
