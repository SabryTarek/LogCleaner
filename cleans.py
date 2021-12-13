import sys, getopt, shutil, yara, glob, os, errno



def get_args(argv):
    yara_file = ''
    input_folder = ''
    try:
       opts, args = getopt.getopt(argv,"hy:f:",["yara=","folder="])
    except getopt.GetoptError:
       print('cleans.py -y <yaraFile> -f <folderToScan>')
       sys.exit(2)
    for opt, arg in opts:
       if opt == '-h':
          print('cleans.py -y <yaraFile> -f <folderToScan>')
          sys.exit()
       elif opt in ("-y", "--yara"):
          yara_file = arg
       elif opt in ("-f", "--folder"):
          input_folder = arg
    print('yaraFile file is :',yara_file)
    print('inputFolder file is ', input_folder)

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
    
    fp = open(yara_file,'r')
    for i, line in enumerate(fp):
        if keyword in line:
            result = bytearray(line.replace(keyword,"").replace("//","").strip().encode())
            break

    print('Replacement string: ', result)

    return result
    

def process_folder(yara_file, input_folder):
    _, files =scandir(input_folder)
    rule = yara.compile(yara_file)
    replacement= get_replacement_string(yara_file)

    for file in files:
        print("\n\n", file)
        output_file_path = ".\\OUTPUT" + file[1:]
        matches = rule.match(file)

        # Read in the file
        with open(file, 'rb') as file :
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
            except OSError as exc: # Guard against race condition
                if exc.errno != errno.EEXIST:
                    raise

        # Write the replaced output
        with open(output_file_path , 'wb') as file:
            file.write(filedata)
            print("\nnew file created at", output_file_path)

def main(argv):
   yara_file, input_folder = get_args(argv)
   process_folder(yara_file, input_folder)
   #TODO: We need to write to the output a summarry of the changes, a logical one
   #    A list of File Name => How many hits, changes, Outout name


if __name__ == "__main__":
   main(sys.argv[1:])