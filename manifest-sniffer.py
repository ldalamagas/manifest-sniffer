#!/usr/bin/python

import argparse
import glob
import sys
import os
import re
from zipfile import ZipFile, BadZipfile, LargeZipFile


def get_jars(path):
    pattern = os.path.join(path, "*.jar")
    return glob.glob(pattern)


def get_manifest_value(jar, manifest_property):
    manifest_path = "META-INF/MANIFEST.MF"
    with ZipFile(jar, "r") as jar:

        manifest = jar.read(manifest_path)

        # Transform it so there is one line per property and value
        lines = manifest.replace("\r\n ", "").split("\r\n")
        properties = {}

        # Create a dictionary containing property:value
        for line in lines:
            if line != "":
                split_line = line.split(": ")
                properties[split_line[0]] = split_line[1]

        if manifest_property in properties.keys():
            return properties[manifest_property]
        else:
            return ""


def get_package_names(manifest_line):
    # split by commas followed by any letter
    pattern = re.compile(r'[,](?=[a-z,A-Z])')
    package_mixed_info = pattern.split(manifest_line)
    packages = []
    for text in package_mixed_info:
        packages.append(text.split(";")[0])
    return packages


def create_argument_parser():
    description = """
    Scans the given jar's MANIFEST.MF file Import or Export Package section for a package
    """
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("-i", "--imports", help="Checks for the given package in the Import-Package value")
    parser.add_argument("-e", "--exports", help="Checks for the given package in the Export-Package value")
    parser.add_argument("-f", "--file", help="The jar to search in")
    parser.add_argument("-d", "--directory", help="Search all the jars in the given directory")
    parser.add_argument("--detect-double-exports", action="store_true", help="Search for double exports in directory")
    parser.add_argument("--detect-double-imports", action="store_true", help="Search for double imports in manifest")

    return parser


def print_imports(jar):
    import_package_key = "Import-Package"
    import_error_message = "Error while trying to get imported packages"
    try:
        imported_packages = get_package_names(get_manifest_value(jar, import_package_key))
        if arguments.imports in imported_packages:
            print("%s imports %s" % (jar, arguments.imports))
    except RuntimeError:
        print("%s, can I read %s?" % (import_error_message, jar))
    except KeyError:
        print("%s, does %s has a MANIFEST.MF?" % (import_error_message, jar))
    except BadZipfile:
        print("%s, %s is not a valid zip file!" % (import_error_message, jar))
    except IOError:
        print("%s, are you sure %s exists?" % (import_error_message, jar))
    except LargeZipFile:
        print("%s, %s requires ZIP64 functionality but it is not enabled." % (import_error_message, jar))
    except TypeError:
        print("%s, was unable to parse manifest of %s, am I running with python 2?" % (import_error_message, jar))


def print_exports(jar):
    export_package_key = "Export-Package"
    export_error_message = "Error while trying to get exported packages"
    try:
        exported_packages = get_package_names(get_manifest_value(jar, export_package_key))
        if arguments.exports in exported_packages:
            if arguments.detect_double_exports is True:
                for exported_package in exported_packages:
                    if exported_package not in exported_package_counter.keys():
                        exported_package_counter[exported_package] = 0
                    else:
                        exported_package_counter[exported_package] += 1
            print("%s exports %s" % (jar, arguments.exports))
    except RuntimeError:
        print("%s, can I read %s?" % (export_error_message, jar))
    except KeyError:
        print("%s, does %s has a MANIFEST.MF?" % (export_error_message, jar))
    except BadZipfile:
        print("%s, %s is not a valid zip file!" % (export_error_message, jar))
    except IOError:
        print("%s, are you sure %s exists?" % (export_error_message, jar))
    except LargeZipFile:
        print("%s, %s requires ZIP64 functionality but it is not enabled." % (export_error_message, jar))
    except TypeError:
        print("%s, was unable to parse manifest of %s, am I running with python 2?" % (export_error_message, jar))


def print_double_exports():
    for exported_package in exported_package_counter.keys():
        if exported_package_counter[exported_package] > 1:
            print("%s is exported %d times" % (exported_package, exported_package_counter[exported_package]))


def print_double_imports(jar, imported_package_counter):
    for imported_package in imported_package_counter.keys():
        if imported_package_counter[imported_package] > 1:
            print("%s is imported %d times in %s" % (imported_package, imported_package_counter[imported_package], jar))


def detect_double_imports(jar):
    import_package_key = "Import-Package"
    error_message = "Error while detecting double imports"
    imported_package_counter = {}
    try:
        manifest_line = get_manifest_value(jar, import_package_key)
        if manifest_line != "":
            imported_packages = get_package_names(manifest_line)
        else:
            return
        for imported_package in imported_packages:
            if imported_package not in imported_package_counter.keys():
                imported_package_counter[imported_package] = 0
            else:
                imported_package_counter[imported_package] += 1
        print_double_imports(jar, imported_package_counter)
    except RuntimeError:
        print("%s, can I read %s?" % (error_message, jar))
    except KeyError:
        print("%s, does %s has a MANIFEST.MF?" % (error_message, jar))
    except BadZipfile:
        print("%s, %s is not a valid zip file!" % (error_message, jar))
    except IOError:
        print("%s, are you sure %s exists?" % (error_message, jar))
    except LargeZipFile:
        print("%s, %s requires ZIP64 functionality but it is not enabled." % (error_message, jar))
    except TypeError:
        print("%s, was unable to parse manifest of %s, am I running with python 2?" % (error_message, jar))


def main():
    if len(sys.argv) < 2:
        argument_parser.print_help()
        exit(1)

    if arguments.file is not None:
        if arguments.imports is not None:
            print_imports(arguments.file)

        if arguments.exports is not None:
            print_exports(arguments.file)

        if arguments.detect_double_imports is True:
            detect_double_imports(arguments.file)

    if arguments.directory is not None:
        jars = get_jars(arguments.directory)
        for jar in jars:
            if arguments.imports is not None:
                print_imports(jar)

            if arguments.exports is not None:
                print_exports(jar)

        if arguments.detect_double_imports is True:
            for jar in jars:
                detect_double_imports(jar)

    if arguments.detect_double_exports is True:
        print_double_exports()

    exit(0)

if __name__ == '__main__':
    argument_parser = create_argument_parser()
    arguments = argument_parser.parse_args()
    exported_package_counter = {}
    main()

