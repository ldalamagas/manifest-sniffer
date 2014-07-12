#!/usr/bin/python

import argparse
import glob
import os
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
    package_mixed_info = manifest_line.split(",")
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


def print_exports(jar):
    export_package_key = "Export-Package"
    export_error_message = "Error while trying to get exported packages"
    try:
        exported_packages = get_package_names(get_manifest_value(jar, export_package_key))
        if arguments.imports in exported_packages:
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


def main():
    if arguments.file is not None:
        if arguments.imports is not None:
            print_imports(arguments.file)

        if arguments.exports is not None:
            print_exports(arguments.file)

    if arguments.directory is not None:
        for jar in get_jars(arguments.directory):
            if arguments.imports is not None:
                print_imports(jar)

            if arguments.exports is not None:
                print_exports(jar)

if __name__ == '__main__':
    argument_parser = create_argument_parser()
    arguments = argument_parser.parse_args()
    main()

