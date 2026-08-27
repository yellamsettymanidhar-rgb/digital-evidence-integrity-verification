# Viva Preparation — Questions & Answers

Answers are written the way you'd say them out loud — concise, and pointing
to the exact file/line if the examiner asks "show me."

---

**Q: What is digital evidence?**
Any information of probative value stored or transmitted in digital form —
documents, images, videos, audio, logs — that could be used in an
investigation or legal proceeding.

**Q: What is digital forensics?**
The application of scientific methods to collect, preserve, analyze, and
present digital evidence in a way that maintains its integrity and is
defensible if challenged.

**Q: What is evidence integrity?**
The assurance that a piece of evidence has not been altered, accidentally
or deliberately, since it was collected. It's about *change detection*, not
about proving the evidence is true or original.

**Q: What is hashing?**
A one-way mathematical function that takes an input of any size and
produces a fixed-size output (the "hash" or "digest"). The same input
always produces the same output, and there's no practical way to reverse
the process or find a different input with the same output.

**Q: What is SHA-256?**
Secure Hash Algorithm, 256-bit output. Part of the SHA-2 family, published
by NIST. It produces a 64-character hexadecimal digest and is the current
standard for integrity verification because no practical collision attack
is known against it (unlike MD5 and SHA-1, both of which are broken for
this purpose).

**Q: Why SHA-256 instead of simply comparing files byte-by-byte?**
Three reasons: (1) it scales — comparing two 64-character strings is
instant regardless of whether the file is 1 KB or 10 GB; (2) it's
storable/shareable — you can record a hash in a report or database row,
you can't practically "store a copy of the whole file" as your integrity
reference; (3) direct comparison requires having both files in the same
place at the same time, whereas a hash lets you verify against a reference
recorded long ago and far away.

**Q: What's the difference between hashing and encryption?**
Hashing is one-way and keyless — you cannot recover the original input from
the hash, and the goal is to *detect change*. Encryption is two-way and
key-based — the ciphertext is meant to be decrypted back into the original
data by whoever holds the key, and the goal is to *hide content*. This
system hashes evidence (to detect tampering); it does not encrypt it.

**Q: How does the system detect tampering?**
At registration, it computes SHA-256 over the exact bytes uploaded and
stores that hash permanently (`evidence.sha256_hash`, never overwritten).
At verification, it computes SHA-256 over the newly-submitted file and
compares the two digests with `hmac.compare_digest()` in
`utils/hashing.py`. Any difference at all means the file changed.

**Q: What happens when one byte changes?**
SHA-256 exhibits the *avalanche effect*: changing a single bit anywhere in
the input flips roughly half the output bits, in a way that looks
unpredictable. You can see this live in the demo — Demo 3 changes one
character in a text file and the resulting hash is completely different
from the original, with no visible pattern connecting the two. The UI even
highlights exactly which hex characters differ.

**Q: Where is the original hash stored?**
In the `evidence` table, column `sha256_hash`, written once at upload time
in `routes/evidence.py` and never updated afterward — see `models.py ::
create_evidence()`. Every later verification reads this value but never
writes to it; only `verification_logs` accumulates new rows.

**Q: What is chain of custody?**
A chronological record of who handled a piece of evidence and what they did
with it, from collection to presentation — used to show the evidence
wasn't tampered with or swapped along the way. Here it's implemented in the
`chain_of_custody` table, with an entry written automatically every time
evidence is registered, uploaded, viewed, verified, downloaded, or
archived (see `models.py :: add_custody_entry()` and its call sites across
`routes/`).

**Q: What are the limitations of this system?**
It's a project-level implementation, not a legally admissible forensic
chain of custody — that would also require physical evidence handling
procedures and legal/procedural controls this software can't provide. A
hash match proves the file is unchanged *since registration*; it says
nothing about the file's authenticity or origin *before* that point.
SQLite is used by default, which is fine for a demo but not for concurrent
multi-user production use. Full details are in the README's Limitations
section.

**Q: What security measures are implemented?**
- Passwords hashed with `werkzeug.security` (scrypt), never stored in
  plaintext — verified by `tests/test_app.py :: test_13`.
- File type allow-list rejects anything not evidence-appropriate
  (`utils/security.py :: allowed_file`).
- File size capped via Flask's `MAX_CONTENT_LENGTH` (returns HTTP 413).
- Secure, randomized filenames on disk via `werkzeug.utils.secure_filename`
  + a UUID4 prefix, neutralizing path traversal — verified by `test_14`.
- Parameterized SQL everywhere in `models.py` (`?` placeholders), so no
  string-built queries — this is what prevents SQL injection.
- Session cookies are HttpOnly and SameSite=Lax.
- Role-based access control (`admin` vs `investigator`) enforced by
  decorators (`@login_required`, `@roles_required`) on every sensitive route.
- No public self-registration — accounts are created only by an admin,
  which limits who can obtain investigator credentials in the first place.
- Uploaded files are never executed — they're saved to disk and only ever
  read back for hashing or download, never invoked as code.

**Q: Why did you choose Python/Flask?**
Flask is a lightweight, unopinionated framework — appropriate for a
project this size, where the goal is to clearly demonstrate the forensic
workflow rather than wrestle with a heavier framework's conventions. Its
routing and templating (Jinja2) map directly onto the module structure the
brief asked for, and Python's `hashlib` gives a one-line, standard-library
SHA-256 implementation with no external dependency needed for the core
integrity mechanism.

**Q: Why did you use a database instead of, say, flat files?**
A database gives atomic writes, relational integrity (foreign keys tying
verification logs and custody entries back to a specific evidence record),
indexed search, and concurrent access safety — all of which flat files
would require reimplementing badly. It also makes the audit trail
queryable (e.g., "show all failed verifications this week") in a way a
folder of text files wouldn't support.

**Q: Why SQLite instead of MySQL, when the brief mentioned MySQL?**
For reliability on demo day: SQLite needs no running server process, no
credentials, no network — it's a single file. That removes the most common
last-minute failure mode (a MySQL server that isn't running, or wrong
connection details) right before a viva. The schema and all queries are
written in portable SQL specifically so switching to MySQL later is a
small, mechanical change — documented in the README — rather than a
rewrite, if a MySQL requirement is specifically enforced.

**Q: Why not use an ORM like SQLAlchemy?**
Keeping the SQL visible in `models.py` makes it straightforward to explain
exactly what each query does in a viva, and keeps the dependency list
short. For a project this size, hand-written parameterized queries are
easier to reason about than an ORM's abstraction layer.

**Q: Is SHA-256 an AI or machine learning technique?**
No. It's a deterministic cryptographic algorithm — the same input always
produces the same output, and there's no training, no model, no
statistical inference involved anywhere in the hashing or verification
path. Nothing in this system claims otherwise.

**Q: How would an attacker try to defeat this system, and what stops them?**
- *Forge a hash collision* (craft a different file with the same SHA-256):
  computationally infeasible with current techniques — that's the whole
  point of using SHA-256 over broken algorithms like MD5.
- *Tamper with the stored hash in the database directly*: outside this
  application's threat model (that would require database access, at which
  point broader system security applies) — a production deployment would
  add database access controls and, ideally, signed/append-only audit logs.
- *Upload a malicious executable disguised as evidence*: blocked by the
  extension allow-list, and even permitted file types are never executed —
  only hashed, stored, and served back for download.
- *Path traversal via filename* (e.g. `../../etc/passwd`): neutralized by
  `secure_filename()` plus a UUID-randomized filename on disk.
