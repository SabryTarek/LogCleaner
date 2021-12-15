import sys
import getopt
import shutil
import yara
import glob
import os
import errno
from pathlib import Path


class RequiredOptions:
    def __init__(self, options_long=[]):

        self.required_options = options_long

    def add(self, option):

        if option not in self.required_options:
            self.required_options.append(option)

    def resolve(self, option):

        if option in self.required_options:
            self.required_options.remove(option)

    def optionsResolved(self):
        if len(self.required_options):
            return False
        else:
            return True


class CMDLineOption:
    def __init__(self, name, mandatory, flagnamelong, flagnameshort, description, ommissionerrmsg, longhelp):
        self.name = name
        self.mandatory = mandatory
        self.flagnamelong = flagnamelong
        self.flagnameshort = flagnameshort
        self.description = description
        self.errormsg = ommissionerrmsg
        self.longhelp = longhelp


def usage():
    print('Usage: ./cleans.py -y <yaraFile> -f <folderToScan> -o <outputfolder>')


def get_args(argv):

    help_option = CMDLineOption("help", False, "help=", "h", "Help", "", "")
    yarafile_option = CMDLineOption(
        "yara", True, "yara=", "y:", "speficy yara rules file", "You must specify a Yara rules file", "")
    folder_option = CMDLineOption(
        "folder", True, "folder=", "f:", "speficy target folder to cleanse", "You must specify a folder to scan", "")
    output_option = CMDLineOption(
        "output", True, "output=", "o:", "speficy output folder with cleansed files", "You must specify a desitination folder", "")

    options_list = []

    options_list.append(help_option)
    options_list.append(yarafile_option)
    options_list.append(folder_option)
    options_list.append(output_option)

    options_short = "".join([s.flagnameshort for s in options_list])

    options_long_mandatory = [s for s in options_list if s.mandatory]

    required_options = RequiredOptions(options_long_mandatory)

    yara_file = ''
    input_folder = ''
    output_folder = ''

    try:
        opts, args = getopt.getopt(
            argv, options_short, options_long_mandatory)

    except getopt.GetoptError:
        print('Error')
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(1)
        elif opt in ("-y", "--yara"):
            yara_file = arg
            if (not os.path.isfile(yara_file)):
                print(f"Cannot open Yara rules file: {yara_file}")
                sys.exit(3)
            required_options.resolve("yara=")
        elif opt in ("-f", "--folder"):
            input_folder = arg
            if (not os.path.isdir(input_folder)):
                print(f"Directory to cleans not found: {input_folder}")
                sys.exit(4)
            required_options.resolve("folder=")
        elif opt in ("-o", "--output"):
            output_folder = arg
            try:
                Path.mkdir(output_folder, parents=True, exist_ok=False)
            except OSError as e:
                if e.errno == errno.EEXIST:
                    print(
                        f"Directory {output_folder} already exists. You must choose another directory or remove it")
                else:
                    print(f"os error: {e.errno}")
                    sys.exit(5)
            required_options.resolve("output=")

    if not required_options.optionsResolved():
        print(
            f"Missing {len(required_options.required_options)} options: {','.join([s.name for s in required_options.required_options])}\n")
        for option in required_options.required_options:
            print(f"   -{option.flagnameshort[0]}: {option.description}")
        print("")
        usage()
        sys.exit(1)

    sys.exit(0)

    print('   Yara rules: ', yara_file)
    print(' Input folder:', input_folder)
    print('Output folder:', input_folder)

    return yara_file, input_folder


def scandir(dir):
    subfolders, files = [], []

    for f in os.scandir(dir):
        if f.is_dir():
            subfolders.append(f.path)
        if f.is_file():
            files.append(f.path)

    for dir in list(subfolders):
        sf, f = scandir(dir)
        subfolders.extend(sf)
        files.extend(f)
    return subfolders, files


def get_replacement_string(yara_file):
    result = b''
    keyword = "$REPLACEMENT$"

    fp = open(yara_file, 'r')
    for i, line in enumerate(fp):
        if keyword in line:
            result = bytearray(line.replace(
                keyword, "").replace("//", "").strip().encode())
            break

    print('Replacement string: ', result)

    return result


def process_folder(yara_file, input_folder, output_folder):
    _, files = scandir(input_folder)

    rule = yara.compile(yara_file)

    replacement = get_replacement_string(yara_file)

    for file in files:
        print("\n\n", file)
        output_file_path = output_folder + file[1:]
        matches = rule.match(file)

        # Read in the file
        with open(file, 'rb') as file:
            filedata = file.read()
            file.close()

        for match in matches:
            print(file.name, "has", len(match.strings), "matches")
            for item in match.strings:
                (original_offset, rule_name, text) = item
                filedata = filedata.replace(text, replacement)

        # create folders if not exists
        if not os.path.exists(os.path.dirname(output_file_path)):
            try:
                os.makedirs(os.path.dirname(output_file_path))
            except OSError as exc:  # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        # Write the replaced output
        with open(output_file_path, 'wb') as file:
            file.write(filedata)
            print("\nnew file created at", output_file_path)


def main(argv):
    yara_file, input_folder = get_args(argv)

    process_folder(yara_file, input_folder)


if __name__ == "__main__":
    main(sys.argv[1:])
