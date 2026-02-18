#!/bin/bash
MIELEIP="$1"
PROTOCOL=https
# Test the following endpoints by outputting the HTTP response to stdout
TARGETS=(
    /WLAN 
    /Ident
    /State
    /profUser/users
    /profUser/roles
    /Security/Cloud
    /Settings
    /profFileTransfer
    /profLock
    /PROF
    /DOP2curl
)

# check if device is reachable, exit if not
ping -c 1 -W 1 "$MIELEIP" > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "Device $MIELEIP is not reachable."
    exit 1
fi  

# testing each endpoint, printing the response
for TARGET in "${TARGETS[@]}"; do
    echo "Testing endpoint: $TARGET"
    curl -H "Authorization: MieleH256 1111111111111111:DD361380F1AB6BC95C3A42144DA458CB58A204A4A509E14B59B7690D1846AAE3" -k "$PROTOCOL://$MIELEIP$TARGET"
    echo -e "\n"
done


curl -H \
  "Authorization: MieleH256 E7AB564588A6AC48:C56417B2C7A04720A4DD03AB45A57B3D1B2288E5CFCDC0FA2A1C8C5BA7183D28B4D3780084138F3A1C99F983985B8B4D16396E0BD712F6BAD5CDEE8B4BCB95BC" \
  -k "https://10.10.6.130/Devices"