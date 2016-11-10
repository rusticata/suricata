#!/bin/sh
set -ex
git clone https://github.com/rusticata/rusticata -b master
(cd rusticata && cargo build)
