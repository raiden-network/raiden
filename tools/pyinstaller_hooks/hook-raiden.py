import glob
import os
import sys

import pkg_resources


WEBUI_BASE_PATH = 'raiden/ui/web/dist'

datas = []
binaries = []


# This is only needed until https://github.com/pyinstaller/pyinstaller/issues/3033 is fixed
def copy_metadata(package_name):
    dist = pkg_resources.get_distribution(package_name)
    metadata_dir = dist.egg_info
    return [(metadata_dir, metadata_dir[len(dist.location) + len(os.sep):])]


# Add metadata of all required packages to allow pkg_resources.require() to work
required_packages = [('raiden', [])]
while required_packages:
    req_name, req_extras = required_packages.pop()
    for req in pkg_resources.get_distribution(req_name).requires(req_extras):
        required_packages.append((req.project_name, list(req.extras)))
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
