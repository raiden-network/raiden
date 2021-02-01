import glob
import os
import sys

import pkg_resources

datas = []
binaries = []


# This is only needed until https://github.com/pyinstaller/pyinstaller/issues/3033 is fixed
def copy_metadata(package_name):
    dist = pkg_resources.get_distribution(package_name)
    metadata_dir = dist.egg_info
    return [(metadata_dir, metadata_dir[len(dist.location) + len(os.sep) :])]


# Add metadata of all required packages to allow pkg_resources.require() to work
required_packages = [("raiden", [])]
processed_packages = set()  # break out of circular dependencies
while required_packages:
    req_name, req_extras = required_packages.pop()
    for req in pkg_resources.get_distribution(req_name).requires(req_extras):
        dep_tuple = (req.project_name, tuple(req.extras))
        if dep_tuple in processed_packages:
            continue

        required_packages.append(dep_tuple)
        processed_packages.add(dep_tuple)
    try:
        datas.extend(copy_metadata(req_name))
    except AssertionError:
        pass

if sys.platform == "darwin":
    # Include newer (Homebrew) OpenSSL libs if available
    openssl_lib_paths = ["/usr/local/Cellar/openssl/"]
    for path in openssl_lib_paths:
        if os.path.exists(path):
            libpath = os.path.join(path, os.listdir(path)[-1], "lib")
            for lib in glob.glob("{}/*.dylib".format(libpath)):
                binaries.append((lib, "."))
