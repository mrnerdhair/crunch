#!/bin/sh
base64 -d | nc "$1" "$2" | base64
