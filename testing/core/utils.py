#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# File name          : utils.py
# Author             : Podalirius (@podalirius_)
# Date created       : 09 july 2024


import json
import os
import random
import string


def find_testCases():
    search_path = os.path.join(os.path.dirname(__file__), os.path.join("..","tests"))

    testCases = {}
    for root, dirs, files in os.walk(search_path):
        for file in files:
            if file.endswith(".json"):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as f:
                    data = json.loads(f.read())

                    category = data["category"]
                    subcategory = data["subcategory"]

                    if category not in testCases.keys():
                        testCases[category] = {}
                    if subcategory not in testCases[category].keys():
                        testCases[category][subcategory] = {}
                    
                    testCases[category][subcategory][file_path] = data
                    
    return testCases


def parseLogfileContents(contents):
    parsed = []

    prompt_start = "⏺[\\\\1"
    prompt_end = "\\]> "

    buffer = None
    command = None
    for line in contents.split('\n'):
        # Detect prompt
        if line.startswith(prompt_start) and (prompt_end in line):
            # Save last state 
            if (command is not None) and (buffer is not None):
                parsed.append({
                    "command": command,
                    "output": buffer,
                    "error": any([l.startswith("[error]") for l in buffer]),
                    "traceback": any([l.startswith("Traceback") for l in buffer]),
                })
                command = None
                buffer = None
            # 
            command = line.strip().split(prompt_end, 1)[1]
        else:
            if buffer is None:
                buffer = []
            buffer.append(line)
    
    # Save final command 
    if (command is not None) and (buffer is not None):
        parsed.append({
            "command": command,
            "output": buffer,
            "error": any([l.startswith("[error]") for l in buffer]),
            "traceback": any([l.startswith("Traceback") for l in buffer]),
        })
        command = None
        buffer = None

    return parsed


def render(options, s):
    random_string_8 = ''.join([random.choice(string.ascii_letters + string.digits) for k in range(8)])
    random_string_16 = ''.join([random.choice(string.ascii_letters + string.digits) for k in range(16)])

    output = s.format(
        auth_domain=options.auth_domain,
        auth_username=options.auth_username,
        auth_password=options.auth_password,
        target_host=options.host,
        target_port=options.port,
        random_string=random_string_8,
        random_string_8=random_string_8,
        random_string_16=random_string_16
        # auth_nt_hash=nthash(options.auth_password),
        # auth_lm_hash=lmhash(options.auth_password)
    )

    return output
