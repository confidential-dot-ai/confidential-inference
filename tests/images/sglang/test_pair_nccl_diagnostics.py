"""Adversarial tests of the recorder projection and the final log schema."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'images/sglang'))
sys.path.insert(0,str(ROOT/'images/sglang-router'))
import pair_supervisor as pair
fork=Path(os.environ.get('SGLANG_FORK_ROOT','/var/lib/user-data/sglang-recovery/worker-clean'))
spec=importlib.util.spec_from_file_location('nccl_projection',fork/'python/sglang/srt/utils/pair_nccl_diagnostics.py')
projection=importlib.util.module_from_spec(spec);spec.loader.exec_module(projection)


def entry():
    return {'profiling_name':'nccl:broadcast','collective_seq_id':7,'is_p2p':False,'pg_id':2,
            'input_sizes':[[2,4]],'input_dtypes':['Float'],'state':'started',
            'time_created_ns':100,'time_discovered_started_ns':120,
            'timeout_ms':600000}


class RecorderPrivacyTests(unittest.TestCase):
    def test_only_reviewed_metadata_survives_private_recorder_fields(self):
        value=entry()
        private='PRIVATE_PROMPT_RESPONSE_CREDENTIAL_IDENTITY'
        value.update(thread_name=private,process_group=private,frames=[private],
                     input_values=[private],message=private,locals={'secret':private})
        raw=json.dumps({'pg_config':{'description':private},'nccl_comm_state':private,'entries':[value]})
        rows,rejected=projection.project_trace(raw)
        self.assertEqual(0,rejected)
        self.assertEqual([{'op':'broadcast','state':'started','sequence':7,'count':8,'group_id':2,
                           'bytes':32,'created_ns':100,'started_ns':120,'timeout_ms':600000}],rows)
        self.assertNotIn(private,json.dumps(rows))
        self.assertIsNotNone(pair.reviewed_event({'event':'nccl_collective','role':'decode','rank':1,**rows[0]}))

    def test_malformed_or_private_values_cannot_become_metadata(self):
        private='PRIVATE_PROMPT_RESPONSE_API_CREDENTIAL'
        for field,bad in (('profiling_name','nccl:broadcast '+private),('state',private),
                          ('collective_seq_id',private),('collective_seq_id',True),
                          ('input_sizes',[[private]]),('input_sizes',[[2**63]]),
                          ('input_sizes',[[True]])):
            value=entry();value[field]=bad
            rows,rejected=projection.project_trace(json.dumps({'entries':[value]}))
            self.assertEqual([],rows)
            self.assertEqual(1,rejected)
        value=entry();value['input_dtypes']=[private]
        rows,_=projection.project_trace(json.dumps({'entries':[value]}))
        self.assertNotIn(private,json.dumps(rows))
        self.assertNotIn('bytes',rows[0])

    def test_records_and_payload_size_are_bounded(self):
        rows,rejected=projection.project_trace(json.dumps({'entries':[entry() for _ in range(1000)]}))
        self.assertEqual(32,len(rows));self.assertEqual(968,rejected)
        for raw in ('x'*1048577,'{"entries":"PRIVATE_TEXT"}','[]'):
            with self.assertRaises(ValueError):projection.project_trace(raw)

    def test_log_schema_rejects_unreviewed_names_and_fields(self):
        base={'event':'nccl_collective','role':'decode','rank':0,'op':'broadcast',
              'state':'started','sequence':7,'count':8}
        self.assertIsNotNone(pair.reviewed_event(base))
        for field in ('prompt','response','tensor','message','process_group','thread_name','api_key','rid'):
            self.assertIsNone(pair.reviewed_event({**base,field:'PRIVATE_TEXT'}))
        for field in ('op','state','sequence','count'):
            for bad in ('PRIVATE_TEXT',True,[],{},float('nan')):
                self.assertIsNone(pair.reviewed_event({**base,field:bad}))


if __name__=='__main__':unittest.main()
