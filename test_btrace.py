import unittest
import blocktrace as btrace
import sample
import hashlib
import json
from tracewrapper import tracewrapper

class test(unittest.TestCase):
    def test_verifychainstandalone(self):
        inst1 = btrace.BlockTrace()
        inst1.start()
        sample.fib(50)
        inst1.stop()
        for n, b in inst1.block.items():
            if not n==0:
              thash=b["Hash"]
              b["Hash"]=inst1.block[n-1]["Hash"]
              hlib=hashlib.sha1()
              hlib.update(bytes(json.dumps(b), 'utf-8'))
              try:
                  newhash=hlib.hexdigest()
              except AssertionError:
                  newhash=hlib.hexdigest(20)
              assert thash==newhash, f"Hashes are not equal for block {n} old hash= {hash} new hash = {newhash}"
              b["Hash"]=thash

    def test_verifyblockstandalone(self):
        inst1 = btrace.BlockTrace()
        inst1.start()
        sample.fib(50)
        inst1.stop()
        assert inst1.verifyblock(inst1.block[3],inst1.block[2]["Hash"])

    def test_verifychainmethod(self):
        inst1 = btrace.BlockTrace()
        inst1.start()
        sample.fib(50)
        inst1.stop()
        inst2 = btrace.BlockTrace()
        result=inst2.verifychain(inst1.block)

        assert result=="" or result is None, result

        inst3 = btrace.BlockTrace(_new_hash=False)
        inst3.start()
        sample.fib(50)
        inst3.stop()
        inst4 = btrace.BlockTrace(_new_hash=False)
        result=inst4.verifychain(inst3.block)

        assert result=="" or result is None, result

    def test_verifyhook(self):
        inst1 = btrace.BlockTrace(_each_block_hook=testhook)
        inst1.start()
        sample.fib(50)
        inst1.stop()

#Dependencies

def testhook(_iter, _block):
    assert _iter is not None or _block is not None, f"Data missing for _each_block_hook _iter = {_iter} block = {_block}"
