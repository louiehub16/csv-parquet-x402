
import json, base64, time
from eth_account import Account

USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
acct = Account.from_key("0x" + "11"*32)
payTo = "0x795dCA28d0e8a0E5d19D689163f125a7da1D0B83"
domain = {"name": "USD Coin", "version": "2", "chainId": 8453, "verifyingContract": USDC}
types = {"TransferWithAuthorization": [
    {"name":"from","type":"address"},{"name":"to","type":"address"},
    {"name":"value","type":"uint256"},{"name":"validAfter","type":"uint256"},
    {"name":"validBefore","type":"uint256"},{"name":"nonce","type":"bytes32"}]}
now = int(time.time())

def make(value, va_off, vb_off, nonce_hex):
    msg = {"from": acct.address, "to": payTo, "value": value,
           "validAfter": now + va_off, "validBefore": now + vb_off,
           "nonce": "0x" + nonce_hex*32}
    signed = Account.sign_typed_data(acct.key, full_message={
        "types": types, "primaryType": "TransferWithAuthorization",
        "domain": domain, "message": msg})
    raw = bytes(signed.signature)
    accepted = {"scheme":"exact","network":"eip155:8453","amount":str(value),
                "asset":USDC,"payTo":payTo,"maxTimeoutSeconds":600,
                "extra":{"name":"USD Coin","version":"2"}}
    payment = {"x402Version":2,"scheme":"exact","network":"eip155:8453","accepted":accepted,
      "payload":{"signature":{"r":"0x"+raw[:32].hex(),"s":"0x"+raw[32:64].hex(),"v":raw[64]},
                 "authorization":msg}}
    return base64.urlsafe_b64encode(json.dumps(payment).encode()).decode().rstrip("=")

out = {
  "header_b64url": make(10000, -5, 550, "ab"),
  "expected_amount": "10000",
  "payer_expected": acct.address,
  "merchant": payTo,
  "wrong_amount_header_b64url": make(1, -5, 550, "cd"),
  "expired_header_b64url": make(10000, -500, -400, "ef"),
}
p = r"C:\Users\John Doe\Desktop\csv-parquet-x402\src\e2e_vector.json"
json.dump(out, open(p, "w"), indent=1)
print("minted")
