#!/bin/bash

echo "Creating $1 files"

for i in $(seq 1 $1); do
    head -c 1K < /dev/urandom > testfile-$i.js
done

