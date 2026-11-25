import hashlib
import hmac
from argon2.low_level import hash_secret_raw, Type

CAR = (
        '!@#$%^&*()'
        '1234567890'
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        'abcdefghijklmnopqrstuvwxyz'
    ) # list of characters that will make up the generated password

def generate_password(identifier, password, mdp_size=23):
    if not identifier:
        raise ValueError("The ID cannot be empty.")

    if not password:
        raise ValueError("The master password cannot be empty.")

    if mdp_size <= 0:
        raise ValueError("The length must be positive.")

    # Conversion of the master password and identifier to bytes
    password_bytes = password.encode("utf-8")
    context = identifier.encode("utf-8")

    # Creating a deterministic 16-byte salt
    salt = hashlib.sha256(
        b"BrewKey-Argon2id-salt-v2:"
        + len(context).to_bytes(4, "big")
        + context
    ).digest()[:16]

    # Key Derivation with Argon2id to prevent brute-force attacks
    key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=1,
        hash_len=32,
        type=Type.ID
    )

    result = []
    counter = 0
    alphabet_size = len(CAR)

    limit = (256 // alphabet_size) * alphabet_size # rejection sampling: Allowing for unbiased and uniform character selection

    while len(result) < mdp_size:
        message = (
            b"BrewKey-v2:"
            + len(context).to_bytes(4, "big")
            + context
            + counter.to_bytes(4, "big")
        )

        block = hmac.new(
            key,
            message,
            hashlib.sha256
        ).digest()

        for byte in block:
            if byte < limit:
                result.append(CAR[byte % alphabet_size])

                if len(result) == mdp_size:
                    break

        counter += 1

    return "".join(result) 


if __name__ == "__main__":
    identifier = "google.com" #input("Identifier : ")
    password = "MyMasterPassw0rd" #input("PassWord : ")

    print("Your password: ", generate_password(identifier, password))