#!/bin/bash

rm -rf out/bin 2>/dev/null
mkdir -p out/bin

./gradlew jar && cp $(ls -tr build/libs/*.jar | tail -1) out/bin/. && chmod 770 out/bin/*.jar

