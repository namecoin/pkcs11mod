#!/bin/sh

so=./libnamecoin.so

nm --dynamic --defined-only --extern-only $so
