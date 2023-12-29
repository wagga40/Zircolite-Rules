from sigma.collection import SigmaCollection
from sigma.backends.sqlite import sqlite
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline, windows_audit_pipeline
from sigma.processing.resolver import ProcessingPipelineResolver

import multiprocessing as mp
from pathlib import Path
import json
import sys
import functools

# Paths
rules_path = r"./sigma/rules/windows/"
ruleset_name_sysmon = "rules_windows_sysmon_pysigma.json"
ruleset_name_windows = "rules_windows_generic_pysigma.json"

def convert_rule(backend, rule):
    try: 
        return backend.convert_rule(rule, "zircolite")[0]
    except Exception as e:
        print(e)

def ruleset_generator(name, output_filename, input_rules, pipelines):

    print(f'[+] Initialisation ruleset : {name}')
    # Create the pipeline resolver
    piperesolver = ProcessingPipelineResolver()
    # Add pipelines
    for pipeline in pipelines:
        piperesolver.add_pipeline_class(pipeline) # Sysmon handling 
    # Create a single sorted and prioritzed pipeline
    combined_pipeline = piperesolver.resolve(piperesolver.pipelines)
    # Instantiate backend, using our resolved pipeline
    sqlite_backend = sqlite.sqliteBackend(combined_pipeline)

    rules = Path(input_rules)
    if rules.is_dir():
        pattern = f"*.yml"
        rule_list = list(rules.rglob(pattern))
    else:
        sys.exit(f"Log path {rules} is not a directory")
    
    rule_collection = SigmaCollection.load_ruleset(rule_list)

    ruleset = []

    print(f'[+] Conversion : {name}')

    pool = mp.Pool()
    ruleset = pool.map(functools.partial(convert_rule, sqlite_backend), rule_collection)
    pool.close()
    pool.join()

    ruleset = [rule for rule in ruleset if rule is not None] # Removing empty results
    ruleset = sorted(ruleset, key=lambda d: d['level']) # Sorting by level
    with open(output_filename, 'w') as outfile:
        json.dump(ruleset, outfile, indent=4, ensure_ascii=True)

if __name__ == '__main__':
    ruleset_generator("sysmon", ruleset_name_sysmon, rules_path, [sysmon_pipeline(), windows_logsource_pipeline()])
    ruleset_generator("generic", ruleset_name_windows, rules_path, [windows_audit_pipeline(), windows_logsource_pipeline()])
