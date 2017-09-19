import glob
import os
import sys

import pkg_resources
from PyInstaller.utils.hooks import copy_metadata


WEBUI_BASE_PATH = 'raiden/ui/web/dist'

datas = []
binaries = []

# Add metadata of all required packages to allow pkg_resources.require() to work
required_packages = ['raiden']
while required_packages:
    req_name = required_packages.pop()
    required_packages.extend(
        req.name
        for req
        in pkg_resources.get_distribution(req_name).requires()
    )
    try:
        datas.extend(copy_metadata(req_name))
    except AssertionError:
        pass

# Include webui while keeping dir structure
for dirpath, _, filenames in os.walk(WEBUI_BASE_PATH):
    for filename in filenames:
        datas.append((os.path.join(dirpath, filename), dirpath))


if sys.platform == 'darwin':
    # Include newer (Homebrew) OpenSSL libs if available
    openssl_lib_paths = ['/usr/local/Cellar/openssl/']
    for path in openssl_lib_paths:
        if os.path.exists(path):
            libpath = os.path.join(path, os.listdir(path)[-1], 'lib')
            for lib in glob.glob("{}/*.dylib".format(libpath)):
                binaries.append((lib, '.'))
