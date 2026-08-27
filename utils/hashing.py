"""
Cryptographic hashing for evidence integrity checks.

Why SHA-256 (viva-ready explanation, kept here so the code and the
justification live next to each other):

- It is a one-way cryptographic hash: computing the hash from a file is
  fast, but reconstructing the file from the hash is computationally
  infeasible. That's what makes it a fingerprint rather than a copy.
- It has strong collision resistance: no known practical way exists to
  produce two different files with the same SHA-256 hash. Older
  algorithms like MD5 and SHA-1 are broken in this respect and are no
  longer considered forensically trustworthy for this purpose.
- The avalanche effect: flipping a single bit anywhere in the file
  changes roughly half the output bits, unpredictably. This is why the
  system can detect a one-byte change instead of needing a byte-by-byte
  file comparison (which wouldn't scale to large evidence files and
  wouldn't produce a short, storable, shareable fingerprint).
- It is a hash, not encryption: hashing is one-way and has no key: you
  cannot "decrypt" a hash back into the file, and the same input always
  produces the same output. Encryption is two-way and reversible with a
  key. The system uses hashing because the goal is to *detect change*,
  not to hide the file's contents.
"""

import hashlib


def compute_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """
    Compute the SHA-256 hex digest of a file on disk, reading it in fixed-size
    chunks rather than loading it into memory all at once. This matters for
    real evidence files (video, disk images) that can be gigabytes in size.
    """
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()


def compute_sha256_from_stream(file_stream, chunk_size: int = 65536) -> str:
    """
    Same as compute_sha256, but for an in-memory/uploaded file stream
    (e.g. a Werkzeug FileStorage object) rather than a path on disk.
    Restores the stream position afterwards so it can still be saved.
    """
    sha256 = hashlib.sha256()
    file_stream.seek(0)
    while True:
        chunk = file_stream.read(chunk_size)
        if not chunk:
            break
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        sha256.update(chunk)
    file_stream.seek(0)
    return sha256.hexdigest()


def hashes_match(hash_a: str, hash_b: str) -> bool:
    """
    Constant-time-ish comparison of two hash strings. Uses hmac.compare_digest
    to avoid timing side-channels — overkill for a student demo, but it's the
    textbook-correct way to compare secrets/fingerprints and is a good viva
    detail ("why not just use ==?").
    """
    import hmac
    return hmac.compare_digest(hash_a.lower().strip(), hash_b.lower().strip())
