"""Make the client secret Family Hub needs for Sign in with Apple. Run it on your own computer.

Apple doesn't issue a fixed client secret: you sign a short-lived one (at most 6 months)
with the private key (.p8 file) you downloaded from your Apple Developer account. Run this
again before it expires and put the new value in the server's APPLE_CLIENT_SECRET.

    python tools/apple_client_secret.py --team-id TEAMID --key-id KEYID \\
        --client-id com.example.familyhub.web --key-file AuthKey_KEYID.p8 > apple_client_secret.txt

The secret is written to standard output only. Your private key stays on this computer:
never copy the .p8 file to the server or into the repository. Uses the `openssl` command.
"""

import argparse
import base64
import json
import subprocess
import sys
import time

MAX_DAYS = 180   # Apple refuses secrets that last longer than 6 months


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def der_to_raw(signature):
    """openssl writes an ECDSA signature as DER; a JWT wants r and s as 32 bytes each."""
    if len(signature) < 8 or signature[0] != 0x30:
        raise ValueError("unexpected signature format from openssl")
    i = 2
    parts = []
    for _ in range(2):
        if signature[i] != 0x02:
            raise ValueError("unexpected signature format from openssl")
        length = signature[i + 1]
        value = signature[i + 2:i + 2 + length].lstrip(b"\x00")
        if len(value) > 32:
            raise ValueError("unexpected signature format from openssl")
        parts.append(value.rjust(32, b"\x00"))
        i += 2 + length
    return parts[0] + parts[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--team-id", required=True, help="your Apple Developer Team ID")
    parser.add_argument("--key-id", required=True, help="the Key ID of the Sign in with Apple key")
    parser.add_argument("--client-id", required=True, help="the Services ID (APPLE_CLIENT_ID)")
    parser.add_argument("--key-file", required=True, help="path to the AuthKey_<KEYID>.p8 file")
    parser.add_argument("--days", type=int, default=MAX_DAYS, help=f"how long it lasts (1-{MAX_DAYS})")
    args = parser.parse_args()
    if not 1 <= args.days <= MAX_DAYS:
        parser.error(f"--days must be between 1 and {MAX_DAYS}")

    now = int(time.time())
    header = {"alg": "ES256", "kid": args.key_id}
    claims = {
        "iss": args.team_id,
        "iat": now,
        "exp": now + args.days * 24 * 3600,
        "aud": "https://appleid.apple.com",
        "sub": args.client_id,
    }
    signing_input = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", args.key_file],
        input=signing_input.encode(), capture_output=True, check=False,
    )
    if result.returncode != 0:
        sys.exit("openssl couldn't sign with that key file: " + result.stderr.decode(errors="replace").strip())
    print(f"{signing_input}.{b64url(der_to_raw(result.stdout))}")
    expires = time.strftime("%Y-%m-%d", time.gmtime(claims["exp"]))
    print(f"This secret expires on {expires}. Make a new one before then.", file=sys.stderr)


if __name__ == "__main__":
    main()
