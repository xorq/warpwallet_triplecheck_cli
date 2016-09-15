# warpwallet_triplecheck_cli

This is another double check for the excellent warpwallet from keybase.io
https://keybase.io/warp/warp_1.0.8_SHA256_5111a723fe008dbf628237023e6f2de72c7953f8bb4265d5c16fc9fd79384b7a.html


In the command line, type :
python getpkey.py "password" "salt"


The output will be the same as warpwallet.


If you want qrcodes, you can type
node warp.js "password" "salt"


The output will have the address, the public key (for your multisig purposes) and the private key.


Enjoy !