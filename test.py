import sys
import getopt
import shutil
from typing import BinaryIO
import yara
import glob
import os
import errno
from pathlib import Path
import datetime
from tqdm import tqdm
import humanize
from collections import defaultdict
in_file="test_data/New folder/test2.txt"
# rule = yara.compile('test.yar')

with open(in_file, "rb") as r:
    with open("ali-test.txt", "wb") as w:
        for block in r.read(4):
            print((block))
            w.write(bytes(block).decode(encoding='UTF-8'))


# # chunked file reading
# from __future__ import division
# import os


# def get_chunks(file_size):
#     chunk_start = 0
#     chunk_size = 0x20000  # 131072 bytes, default max ssl buffer size
#     while chunk_start + chunk_size < file_size:
#         yield (chunk_start, chunk_size)
#         chunk_start += chunk_size

#     final_chunk_size = file_size - chunk_start
#     yield (chunk_start, final_chunk_size)


# def read_file_chunked(file_path):
#     with open(file_path) as file_:
#         file_size = os.path.getsize(file_path)

#         print("File size: {}".format(file_size))

#         progress = 0

#         for chunk_start, chunk_size in get_chunks(file_size):

#             file_chunk = file_.read(chunk_size)

#             # do something with the chunk, encrypt it, write to another file...

#             progress += len(file_chunk)
#             print(
#                 "{0} of {1} bytes read ({2}%)".format(
#                     progress, file_size, int(progress / file_size * 100)
#                 )
#             )


# # if __name__ == '__main__':
# # read_file_chunked('some-file.gif')
