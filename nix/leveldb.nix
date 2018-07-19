{ pkgs , stdenv, fetchFromGitHub }:

stdenv.mkDerivation rec {
  name = "leveldb-${version}";
  version = "1.21-pre";

  src = fetchFromGitHub {
    owner = "google";
    repo = "leveldb";
    rev = "6caf73ad9dae0ee91873bcb39554537b85163770";
    sha256 = "1djwnxmfbflvzqs2vzlxc9ms1yj2pd2dax5vr0xvws26xcdzd0ck";
  };

  buildInputs = [ pkgs.cmake ];
}
