#MIT License
#
#Copyright (c) 2021 Ian Holdsworth
#
#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:
#
#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.
#
#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

import sample
from tracewrapper import tracewrapper
import opcode
import sys
import linecache
import json
from datetime import datetime
import hashlib
from pathlib import *
from deepdiff import DeepDiff
class BlockTrace(tracewrapper.TracerClass):
    """
    Blockchain applied to Trace in order to develop trust between applications
    """
    iter=0
    __cantrace__=False
    def __init__(self, _each_block_hook=None, _genesis="Genesis", _hash="sha1", _globals="On", _locals="On", _builtins="Off",
                 _pathelements=0, _trace_lines=True, _trace_opcodes=False, _new_hash=True, **_deepdiff):
        """
        Initialise BlockTrace

        Parameters:
            _each_block_hook default None
                Hook to a procedure/method to call after each block is generated.
                Hook parameters are block number and the block itself
            _genesis default "Genesis"
                sample text supplied for tyhe initial block this might be a token supplied by a 3rd party or
                it could be just simple plain text.
            _hash default "sha1"
                The hashing algorithm to be used in signing each block.  Any algorithm on Hashlib's guaranteed
                list is supported (though we recommend against using md5 as the implementations are not guaranteed
                across all platforms)
            _globals default "On" (Case insensitive)
                Trace global variables options "On", "Off", "Changes"
                    Note if "Changes" is specified changes will be tracked with Deepdiff
                    https://deepdiff.readthedocs.io/en/latest/ all DeepDiff options are supported
            _locals default "On" (Case insensitive)
                Trace local variables options "On", "Off", "Changes"
                    Note if "Changes" is specified changes will be tracked with Deepdiff
                    https://deepdiff.readthedocs.io/en/latest/ all DeepDiff options are supported
            _builtins default "On" (Case insensitive)
                Trace builtins options "On", "Off", "Changes"
                    Note if "Changes" is specified changes will be tracked with Deepdiff
                    https://deepdiff.readthedocs.io/en/latest/ all DeepDiff options are supported
            _pathelements default 0
                How many path elements (directories) to include with modules
            _trace_lines default True
                Turn on sys.trace's tracelines
            _trace_opcodes default False
                Turn on sys.trace's traceopcodes
            _new_hash default true
                Generate a new instance of hashlib for every block
        """
        self.iter=0
        self.block={}
        self.globs={}
        self.locals={}
        self.built=[]
        self._locals=_locals
        self._globals=_globals
        self._builtins=_builtins
        self._pathelements=_pathelements
        self._hash=_hash
        self._new_hash=_new_hash
        self.block[self.iter]={}
        self.block[self.iter]["DateTime"]=datetime.now().strftime("%d/%m/%Y, %H:%M:%S.%f")
        self._deepdiff=_deepdiff
        self._each_block_hook=_each_block_hook

        if _globals.upper() in ["ON", "CHANGES"]:
            self.block[self.iter]["Globals"]=self.globs
        if _builtins.upper() in ["ON", "CHANGES"]:
            self.block[self.iter]["Builtins"]=self.built
        if _locals.upper() in ["ON", "CHANGES"]:
            self.block[self.iter]["Locals"]=self.locals
        self.block[self.iter]["sample"]=_genesis
        self.hash=self.hashlibwrapper(self._hash)()
        self.hash.update(bytes(json.dumps(self.block[self.iter]), 'utf-8'))
        try:
            self.block[self.iter]["Hash"]=self.hash.hexdigest()
        except:
            self.block[self.iter]["Hash"]=self.hash.hexdigest(20)
        self.tw=tracewrapper.tracewrapper(_trace_lines=_trace_lines, _trace_opcodes=_trace_opcodes)
        self.tw.add_module_exclusion("blocktrace.py")
        self.tw.add(self.trace)

    def verifyblock(self, _block, _previous_hash):
        """
        Verifies a block given it's previous hash.
        note: Will only work if blocktrace is instanciated with _new_hash set to true
        """
        hash=_block["Hash"]
        cpy=_block.copy()
        cpy["Hash"]=_previous_hash
        hlib=self.hashlibwrapper(self._hash)()
        hlib.update(bytes(json.dumps(cpy), 'utf-8'))
        try:
          newhash=hlib.hexdigest()
        except:
          newhash=hlib.hexdigest(20)
        return hash==newhash
    def verifychain(self,_block):
        """
        Verify Blockchain from the start
        """
        for n, b in _block.items():
            if not n==0:
              hash=b["Hash"]
              b["Hash"]=_block[n-1]["Hash"]
              if self._new_hash:
                  self.hash=self.hashlibwrapper(self._hash)()
              self.hash.update(bytes(json.dumps(b), 'utf-8'))
              try:
                  newhash=self.hash.hexdigest()
              except:
                  newhash=self.hash.hexdigest(20)
              if hash!=newhash:
                  return f"Hashes are not equal for block {n} old hash= {hash} new hash = {newhash} _new_hash={self._new_hash}"
              b["Hash"]=hash
            else:
              cpy=b.copy()
              del cpy["Hash"]
              self.hash=self.hashlibwrapper(self._hash)()
              self.hash.update(bytes(json.dumps(cpy), 'utf-8'))


    def hashlibwrapper(self,_hash):
        """
        Wrapper for hashlib
        """
        if not _hash in hashlib.algorithms_guaranteed:
            raise LookupError(_hash+" is not a supported algorithm")
        return getattr(hashlib,_hash)

    def serialisedict(self, _object):
        """
        Strips out unserialisable data from _object
        """
        target={}
        for k, v in _object.items():
            try:
                t=json.dumps(v)
                target[k]=v
            except Exception as e:
                pass #discard unserialisable data

        return target
    def start(self):
        """
        Start tracing
        """
        self.tw.start()
    def stop(self):
        """
        Stop tracing
        """
        self.tw.stop()
    def trace(self, frame, event, arg):
        """
        Hook for tracewrapper https://github.com/BigIan1969/Tracewrapper
        """
        #Serialise Globals
        self.iter+=1
        globs=self.serialisedict(frame.f_globals)

        #get builtins
        built=[]
        for k, v in frame.f_builtins.items():
            built.append(k)

        #get locals
        locals=self.serialisedict(frame.f_locals)

        code = frame.f_code
        offset = frame.f_lasti
        ln= linecache.getline(code.co_filename, frame.f_lineno).strip()

        block={}
        block["DateTime"]=datetime.now().strftime("%d/%m/%Y, %H:%M:%S.%f")
        block["Function"]=code.co_name
        if self._globals.upper() in ["ON", "CHANGES"]:
            if self._globals.upper()=="CHANGES":
                block["Globals"]=DeepDiff(self.globs.items(),globs.items(), **self._deepdiff)
            else:
                block["Globals"]=globs
        if self._builtins.upper() in ["ON", "CHANGES"]:
            if self._builtins.upper()=="CHANGES":
                block["Builtins"]=DeepDiff(self.built,built,**self._deepdiff)
            else:
                block["Builtins"]=built
        if self._locals.upper() in ["ON", "CHANGES"]:
            if self._locals.upper()=="CHANGES":
                block["Locals"]=DeepDiff(self.locals.items(),locals.items(),**self._deepdiff)
            else:
                block["Locals"]=locals
        block["Line Text"]=ln
        block["Event"]=event
        block["Arg"]=arg
        block["Instruction No"]=frame.f_lasti
        block["Opcode"]=opcode.opname[code.co_code[offset]]
        block["Module"]=Path(code.co_filename).name
        block["Path"]="/".join(str(Path(code.co_filename).parent).split("/")[-self._pathelements:])
        block["Line No"]=frame.f_lineno
        block["Hash"]=self.block[self.iter-1]["Hash"]
        if self._new_hash:
            self.hash=self.hashlibwrapper(self._hash)()
        self.hash.update(bytes(json.dumps(block), 'utf-8'))
        try:
            block["Hash"]=self.hash.hexdigest()
        except:
            block["Hash"]=self.hash.hexdigest(20)

        self.block[self.iter]=block
        self.globs=globs
        self.built=built
        self.locals=locals

        if self._each_block_hook is not None:
            self._each_block_hook(self.iter, block)


        return self.trace

#tc=BlockTrace("Test",_globals='changes',_locals="changes",_builtins="changes")
#tracer=tracewrapper.tracewrapper(_trace_opcodes=False)
#tracer.add(tc.trace)
#tc.start()
#tracer.start()
#test.fib(3)
#tracer.stop()
