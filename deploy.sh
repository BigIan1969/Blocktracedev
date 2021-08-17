#!/bin/bash
wd=$(pwd)
cd ../blocktrace
td=$(pwd)
git pull
cd $wd
cp test*.py $td/tests/
cp blocktrace.py $td/src/blocktrace/
cp LICENSE $td
cp pyproject.toml $td
cp setup.cfg $td

