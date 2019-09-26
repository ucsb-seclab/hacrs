#!/usr/bin/env bash

echo "###################### closeness ######################"
python "stats/extract_$1_seeker_results.py" | awk '{print $2}' | xargs echo

echo "###################### triggered ######################"
python "stats/extract_$1_seeker_results.py" | awk '{print $3}' | xargs echo

echo "###################### string_in_binary ######################"
python "stats/extract_$1_seeker_results.py" | awk '{print $4}' | xargs echo

echo ""

echo -n "trigger & string in bin: "
python "stats/extract_$1_seeker_results.py" | grep -i "true true" | wc -l

echo -n "trigger & string not in bin: "
python "stats/extract_$1_seeker_results.py" | grep -i "true false" | wc -l

echo -n "don't trigger & string in bin: "
python "stats/extract_$1_seeker_results.py" | grep -i "false true" | wc -l

echo -n "don't trigger & string not in bin: "
python "stats/extract_$1_seeker_results.py" | grep -i "false false" | wc -l

echo -n "N/A & string in bin: "
python "stats/extract_$1_seeker_results.py" | grep -i "N/A true" | wc -l

echo -n "N/A & string not in bin: "
python "stats/extract_$1_seeker_results.py" | grep -i "N/A false" | wc -l

echo ""

echo -n "String in bin: "
python "stats/extract_$1_seeker_results.py" | awk '{print $4}' | grep -i "true" | wc -l

echo -n "String not in bin: "
python "stats/extract_$1_seeker_results.py" | awk '{print $4}' | grep -i "false" | wc -l

echo -n "trigger: "
python "stats/extract_$1_seeker_results.py" | awk '{print $3}' | grep -i "true" | wc -l

echo -n "don't trigger: "
python "stats/extract_$1_seeker_results.py" | awk '{print $3}' | grep -i "false" | wc -l

echo -n "N/A: "
python "stats/extract_$1_seeker_results.py" | awk '{print $3}' | grep -i "N/A" | wc -l
