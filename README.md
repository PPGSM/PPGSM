# PPGSM
Privacy Preserving Graphical Security Model

Prerequesites
 1. Ubuntu 18.04 above
 2. TFHE, SEAL homomorphic encryption library.

Installation
 1. Install the prerequsites
  To use PPGSM, you need to install two homomorphic encrpytion libraries : TFHE and SEAL.
  
  --Installing TFHE--
  we can get TFHE installation file from here : https://github.com/tfhe/tfhe/tarball/master
  (Github main version would have problem on installing TFHE)
  Once you downloaded installation file, extract the tar.gz file and go to the directory where README.md and LICENSE exists.
  Then, make directory name build using this command : mkdir build
  Go to the build directory : cd build
  Then, using cmake, make installation file at the build directory : cmake ../src
  Finally, using commands below, we install TFHE and are able to use it :
  make
  sudo make install
  
  --Installing SEAL--
  We can get SEAL installation file from this command : git clone https://github.com/microsoft/SEAL
  
