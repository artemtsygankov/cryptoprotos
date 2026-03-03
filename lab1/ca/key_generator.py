import subprocess

def generate_gost_private_key():
    gen = subprocess.Popen(
        [
            "openssl",
            "genpkey",
            "-engine", "gost",
            "-algorithm", "gost2012_256",
            "-pkeyopt", "paramset:TCB"
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )

    pkey = subprocess.run(
        [
            "openssl",
            "pkey",
            "-engine", "gost",
            "-text",
            "-noout"
        ],
        stdin=gen.stdout,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=True
    )

    gen.stdout.close()

    for line in pkey.stdout.decode().splitlines():
        if "Private key:" in line:
            hex_key = line.split(":")[1].strip()
            return bytes.fromhex(hex_key)   # <-- ВАЖНО

    raise RuntimeError("Private key not found")