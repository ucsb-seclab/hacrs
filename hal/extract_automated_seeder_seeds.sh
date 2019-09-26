#!/usr/bin/env bash

for f in /results/?????_?????/automated_seeders/*.tar.gz;
do
    echo $f
    DIRECTORY=$( dirname "$f" )
    FILENAME=$( basename "$f" )
    EXTENSION="${FILENAME##*.}"
    #FILENAME="${FILENAME%.*}"
    #FILENAME="${FILENAME%.*}"
    #RESULT_DIR="${DIRECTORY}/${FILENAME}"
    RESULT_DIR="$DIRECTORY/seeds"
    TMP_DIR=$( mktemp -d )

    if [ -f "${RESULT_DIR}" ]; then
        # This is to fix a weird issue with empty files
        rm -rf "${RESULT_DIR}"
    fi

    if [ ! -d "${RESULT_DIR}" ]; then
        # rm -rf "${RESULT_DIR}"
        mkdir "${RESULT_DIR}"
        tar xfz "$f" -C "$TMP_DIR"
        find "${TMP_DIR}" -type f -exec mv -i {} "${RESULT_DIR}" \;
        rm -rf "${TMP_DIR}"
    fi
done
