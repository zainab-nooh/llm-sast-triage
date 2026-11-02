import os
import sys

def ping():
    os.system("ping -c 1 " + sys.argv[1])   # command injection, on purpose
