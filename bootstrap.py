from __future__ import print_function

import os
import sys
import fnmatch
import imp

script_dir = os.path.dirname(os.path.abspath(__file__))
modules_dir = os.path.join(script_dir, "modules")

def run_patch_from_file(file_path):
    module_name = os.path.splitext(os.path.basename(file_path))[0]

    try:
        module = imp.load_source(module_name, file_path)

        if hasattr(module, 'patch'):
            module.patch()
        else:
            print("Skipped patch: no function patch() in file %s" % file_path)

    except Exception as e:
        print("Error when executing %s file: %s" % (file_path, e))


def scan_and_execute(target_directory):
    target_directory = os.path.abspath(target_directory)

    if target_directory not in sys.path:
        sys.path.insert(0, target_directory)

    for root, dirnames, filenames in os.walk(target_directory):
        for filename in fnmatch.filter(filenames, '*.py'):
            full_path = os.path.join(root, filename)

            if full_path == os.path.abspath(__file__):
                continue

            run_patch_from_file(full_path)


if modules_dir not in sys.path:
    sys.path.insert(0, modules_dir)

scan_and_execute(os.path.join(script_dir, "patches"))
