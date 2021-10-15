import argparse
import ssl
from hashlib import sha1, sha256

from os import sys


parser = argparse.ArgumentParser(description='Get TLS fingerprint from hostname.')
parser.add_argument('hostname', type=str, help='(e.g., duckduckgo.com)')
parser.add_argument('-a', type=int, help='SHA1 or SHA256 algorithm')

def get_der_cert(hostname: str) -> bytes:
    try:
        cert = ssl.get_server_certificate(
            (hostname, 443),
            ssl_version=ssl.PROTOCOL_TLS_CLIENT
        )
        cert_der = ssl.PEM_cert_to_DER_cert(cert)
        
        return cert_der
        
    except Exception as e:
        print(e)


def fingerprint_sha256(hostname: str) -> str:
    der_cert = get_der_cert(hostname)
    return sha256(der_cert).hexdigest()


def fingerprint_sha1(hostname: str) -> str:
    der_cert = get_der_cert(hostname)
    return sha1(der_cert).hexdigest()



if __name__ == '__main__':
    try:
        args = parser.parse_args()
        hostname = args.hostname
        algo = args.a

        if algo == 256:
            print(fingerprint_sha256(hostname))
        else:
            print(fingerprint_sha1(hostname))
    except Exception as e:
        print(e)