#!/bin/bash

BASEDIR=`dirname $0`
VERSION=`grep '__version__ =' tball.py | sed 's/^.*\([0-9][0-9]*\.[0-9][0-9]*\).*$/\1/'`

mkdir tball-$VERSION
cp tball.py tball-$VERSION
zip -r tball-$VERSION.zip tball-$VERSION
rm -r tball-$VERSION
