#!/bin/bash

/usr/bin/python3 /home/tati/feed/ioc-test/feed.py
cd /home/tati/feed/ioc-test
git add .

git commit -m "update"

git push
