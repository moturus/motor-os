#!/usr/bin/env bash

wget --no-parent -r https://download.01.org/perfmon/
rm -rf x86data/perfmon_data
mv download.01.org/perfmon x86data/perfmon_data
cd x86data/perfmon_data
rm `find . | grep index`
cd ../..
rm -rf download.01.org
