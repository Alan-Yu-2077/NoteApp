"""Re-encrypt notes.comment from an old COMMENT_KEY to the current one.

Run once after putting a new COMMENT_KEY in .env, with the old key passed in:

    docker compose run --rm -e COMMENT_KEY_OLD=<old key> web python rotate_comment_key.py

All rows are rewritten in one transaction: if any comment decrypts under
neither key, nothing is changed. Rows already under the new key are skipped,
so running it twice is harmless.
"""
import base64
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import app

OLD_KEY = base64.b64decode(os.environ["COMMENT_KEY_OLD"])


def _decrypt(key, raw, aad):
    try:
        return AESGCM(key).decrypt(raw[:12], raw[12:], aad).decode()
    except (InvalidTag, ValueError):
        return None


def main():
    if len(OLD_KEY) != 32:
        sys.exit("COMMENT_KEY_OLD must be 32 bytes (base64-encoded)")
    if OLD_KEY == app.COMMENT_KEY:
        sys.exit("COMMENT_KEY_OLD equals COMMENT_KEY: nothing to rotate")
    conn = app.get_db()
    conn.autocommit = False
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT id, student_id, class_id, comment FROM notes "
            "WHERE comment LIKE %s FOR UPDATE",
            (app.COMMENT_PREFIX + "%",),
        )
        rotated = 0
        for r in cur.fetchall():
            raw = base64.b64decode(r["comment"][len(app.COMMENT_PREFIX):])
            aad = app._comment_aad(r["student_id"], r["class_id"])
            if _decrypt(app.COMMENT_KEY, raw, aad) is not None:
                continue  # already under the new key
            plain = _decrypt(OLD_KEY, raw, aad)
            if plain is None:
                # Closing without commit discards every update made so far.
                sys.exit(f"note {r['id']} decrypts under neither key; nothing changed")
            cur.execute(
                "UPDATE notes SET comment = %s WHERE id = %s",
                (app.encrypt_comment(plain, r["student_id"], r["class_id"]), r["id"]),
            )
            rotated += 1
        conn.commit()
    finally:
        conn.close()
    print(f"re-encrypted {rotated} comments under the new COMMENT_KEY")
    app.log(f"rotate_comment_key re-encrypted {rotated} comments")


if __name__ == "__main__":
    main()
