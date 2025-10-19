#!/bin/bash

../../ecc $1
# sudo ../../ecli run hardirqs.bpf.o --export-map infos:type=log2_hist,interval=1000
sudo ../../ecli run package.json