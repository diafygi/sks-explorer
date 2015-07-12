import sys
import json

# sks-explorer specific imports
import models

def load_keys_from_dict(keys_dict_list, dry_run=False):
    """Load a list of keys into the database."""
    results = {
        "saved": [],
        "skipped": [],
        "updated": [],
        "no_fingerprint": [],
    }
    for i, k in enumerate(keys_dict_list):
        if (i+1) % 500 == 0:
            sys.stderr.write("Read {} keys...\n".format(i+1))

        # skip keys that don't have fingerprints
        # TODO: lookup by json hash and save it anyway
        if k.get("fingerprint", None) is None:
            results['no_fingerprint'].append(k)
            continue

        # see if this key's fingerprint is already in the database
        existing_keys = models.PublicKey.query.filter_by(fingerprint=k['fingerprint']).all()
        if len(existing_keys) > 0:
            results['skipped'].append(k['fingerprint'])

        # the key is not in the database so save it
        else:
            if not dry_run:
                new_key = models.PublicKey(
                    fingerprint=k['fingerprint'],
                    long_key_id=k['key_id'],
                    short_key_id=k['key_id'][-8:],
                )
                models.db.session.add(new_key)
                models.db.session.commit()

            results['saved'].append(k['fingerprint'])

    return results

def load_keys_from_json(keys_json_list, dry_run=False):
    keys_dict_list = [json.loads(k) for k in keys_json_list]
    return load_keys_from_dict(keys_dict_list, dry_run=dry_run)

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

