#!/bin/bash

STORAGE="storage"

if [ ! -d "$STORAGE" ]; then
    echo "Error: dir '$STORAGE' doesn't exists" >&2
    exit 1
fi

if [ -z "$(ls -A $STORAGE)" ]; then
    echo "Error: dir '$STORAGE' is empty" >&2
    exit 1
fi

./cert2012    "$STORAGE"
./privkey2012 "$STORAGE"

exit 0