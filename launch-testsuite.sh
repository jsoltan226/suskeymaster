#!/bin/sh
dir=$(mktemp -d || printf ''); [ "$dir" = '' ] && exit 1; 
sh testsuite.sh suskeymaster "$dir"; 
rm -rf "$dir"
