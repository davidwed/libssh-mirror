#!/usr/bin/env python3

# esp-idf port support script
#
# Compares files listed in CMakeLists.txt with files available in src

import re
import os
import difflib

def parse_text_file(filename):
    with open(filename, 'r') as file:
        content = file.read()
    match = re.search(r'set\s*\(\s*srcs\s(.*?)\)', content, re.DOTALL)
    if not match:
        return []
    lines = match.group(1).strip().splitlines()
    return [re.sub(r'^\$\{SRC\}/', '', line.strip()) for line in lines if line.strip()]

def scan_directory(dirname):
    c_files = []
    for root, _, files in os.walk(dirname):
        for file in files:
            if file.endswith('.c'):
                relative_path = os.path.relpath(os.path.join(root, file), dirname)
                c_files.append(relative_path.replace('\\', '/'))
    return c_files

def display_diff(list1, list2):
    diff = difflib.unified_diff(
        sorted(list1), sorted(list2),
        fromfile='missing file or duplicate entry in CMakeLists', tofile='not included in CMakeLists',
        lineterm='', n=0
    )
    for line in diff:
        if line.startswith('@'):
            continue
        elif line.startswith('+'):
            print(f"\033[92m{line}\033[0m")  # Green for additions
        elif line.startswith('-'):
            print(f"\033[91m{line}\033[0m")  # Red for deletions
        else:
            print(line)

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    file_to_parse = os.path.join(script_dir, '../libssh/CMakeLists.txt')
    dir_to_scan = os.path.join(script_dir, '../../../src')

    srcs_list = parse_text_file(file_to_parse)
    dir_list = scan_directory(dir_to_scan)
    display_diff(srcs_list, dir_list)

if __name__ == "__main__":
    main()
