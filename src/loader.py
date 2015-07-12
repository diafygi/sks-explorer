import sys
import json
from hashlib import sha256

# sks-explorer specific imports
import models

def load_keys_from_json(keys_json_list, dry_run=False):
    """Load a list of json keys into the database."""
    results = {
        "saved": [],
        "skipped": [],
        "updated": [],
        "no_fingerprint": [],
    }
    for i, kjson in enumerate(keys_json_list):
        if (i+1) % 500 == 0:
            sys.stderr.write("Read {} keys...\n".format(i+1))
        k = json.loads(kjson)

        # skip keys that don't have fingerprints
        # TODO: lookup by json hash and save it anyway
        if not k.get("fingerprint"):
            results['no_fingerprint'].append(k)
            continue

        # see if this key's fingerprint is already in the database
        existing_keys = models.PublicKey.query.filter_by(fingerprint=k['fingerprint']).all()
        if len(existing_keys) > 0:
            # TODO: check to see if an update is needed
            results['skipped'].append(k['fingerprint'])

        # the key is not in the database so save it
        else:
            if not dry_run:

                # get user ids and subkey fingerprints for the search string
                subkeys = u""
                userids = u""
                for p in k.get("packets", []):
                    if p['tag_name'] == "Public-Subkey" and p.get("fingerprint"):
                        subkeys += u" {}".format(p['fingerprint'])
                    elif p['tag_name'] == "User ID" and p.get("user_id"):
                        userids += u" {}".format(p['user_id'])

                # build the search string
                search_string = u"{fingerprint}{subkeys} |{userids}".format(
                    fingerprint=k['fingerprint'],
                    subkeys=subkeys,
                    userids=userids,
                )

                # save the new key
                new_key = models.PublicKey(
                    search_string=search_string,
                    fingerprint=k['fingerprint'],
                    key_id=k['key_id'],
                    json_hash=sha256(kjson).hexdigest(),
                    json_obj=dict((i, j) for i, j in k.items() if i != "packets"),
                )
                models.db.session.add(new_key)
                models.db.session.commit()

                # TODO: insert other rows (userid, subkey, etc.)

            results['saved'].append(k['fingerprint'])

    return results

if __name__ == "__main__":
    """
    Pass json keys output from openpgp-python into stdin one at
    a time. Pass a --dry-run argument if you don't want to save
    or update anything.

    Example:
    zcat sks-dump-0003.pgp.json.gz | python loader.py

    Example that doesn't save or update anything:
    zcat sks-dump-0003.pgp.json.gz | python loader.py --dry-run
    """
    dry_run = sys.argv[-1] == "--dry-run"
    rows = sys.stdin.readlines()
    results = load_keys_from_json(rows, dry_run=dry_run)
    sys.stderr.write(u"""\
Results for {} rows of keys{}:
{} saved
{} skipped
{} updated
{} no_fingerprint
""".format(
        len(rows),
        " (dry_run)" if dry_run else "",
        len(results['saved']),
        len(results['skipped']),
        len(results['updated']),
        len(results['no_fingerprint']),
    ))

