with import (
  builtins.fetchTarball {
    # To update
    #     curl -sI https://nixos.org/channels/nixpkgs-unstable/nixexprs.tar.xz | awk '/Location:/ {print $2}'
    url = "https://d3g5gsiof5omrk.cloudfront.net/nixpkgs/nixpkgs-18.09pre146409.2391d1dbf31/nixexprs.tar.xz";
    # To get the hash
    #     nix-prefetch-url --unpack $url
    sha256 = "08iy7dlyy5f7w1npajrb5pi7gl6mwfjimkkpbcqmkz01bam9bq5x";
  }
) { };

# plyvl requires leveldb >= 1.20
let myLeveldb = callPackage ./leveldb.nix {};

in mkShell rec {

  # Might be needed on mac OS? If so, consider setting on darwin automatically.
  # LC_ALL="en_US.UTF-8";

  # Cannot build wheel otherwise (zip 1980 issue).
  SOURCE_DATE_EPOCH="315532800";

  buildInputs = [
    libffi
    openssl
    gmp
    pkgconfig
    python36
    python36Packages.virtualenv
    solc
    myLeveldb
    libxml2
    libxslt
    go-ethereum
    gitMinimal
    nodejs-8_x
  ];

}
