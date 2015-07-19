import json
from hashlib import sha512

# sks-explorer specific imports
import models

def load_keys_from_json(keys_json_list, dry_run=False):
    """Load a list of json keys into the database."""
    results = {
        "saved": [],
        "skipped": [],
        "updated": [],
    }
    for i, kjson in enumerate(keys_json_list):
        if (i+1) % 500 == 0:
            sys.stderr.write("Read {} keys...\n".format(i+1))

        # skip unchanged full public key packets
        json_sha512 = sha512(kjson).hexdigest()
        unchanged_keys = models.PublicKey.query.filter_by(json_sha512=json_sha512).all()
        if len(unchanged_keys) > 0:
            results['skipped'].append(json_sha512)
            continue

        # see if there's a public key that needs to be updated
        k = json.loads(kjson)
        pub_obj = dict((i, j) for i, j in k.items() if i != "packets")
        pub_sha512 = sha512(json.dumps(pub_obj, sort_keys=True)).hexdigest()
        existing_keys = models.PublicKey.query.filter_by(pub_sha512=pub_sha512).all()

        # update existing keys
        if len(existing_keys) > 0:
            # TODO: actually update the key
            results['updated'].append(json_sha512)
            continue

        # the key is not in the database so save it
        else:
            if not dry_run:

                # get user ids and subkey fingerprints for the search string
                subkeys = []
                userids = []
                for p in k.get("packets", []):
                    if p['tag_name'] == "Public-Subkey" and p.get("fingerprint"):
                        subkeys.append(p['fingerprint'])
                    elif p['tag_name'] == "User ID" and p.get("user_id"):
                        userids.append(p['user_id'])

                # build the search string
                search_string = u"{fingerprint} {subkeys} | {userids}".format(
                    fingerprint=k.get("fingerprint", u""),
                    subkeys=u" ".join(subkeys),
                    userids=u" ".join(userids),
                )

                # create the new key
                new_key = models.PublicKey(
                    search_string=search_string,
                    json_sha512=json_sha512,
                    pub_sha512=pub_sha512,
                    json_raw=kjson,
                )

                # set key details
                new_key.fingerprint = k.get("fingerprint", None)
                new_key.key_id = k.get("key_id", None)
                # TODO: insert other details (algo, created, n, etc.)

                # save the new key
                models.db.session.add(new_key)
                models.db.session.commit()

                # TODO: insert other rows (userid, subkey, etc.)

            results['saved'].append(json_sha512)

    return results

if __name__ == "__main__":
    import sys
    import gzip
    from glob import glob
    from argparse import ArgumentParser
    from argparse import RawTextHelpFormatter

    parser = ArgumentParser(
        formatter_class=RawTextHelpFormatter,
        description="""
Pass json keys output from openpgp-python to insert or update
the sks-explorer database. Pass a --dry-run argument if you
don't want to save or update anything. The keys can be passed in
via stdin (with the "-" parameter) or via a list of files (files
ending in .gz will be read as gzipped files).

Example:
zcat sks-dump-0003.pgp.json.gz | python loader.py -
python loader.py sks-dump-0003.pgp.json
python loader.py sks-dump-0003.pgp.json.gz
python loader.py *.pgp.json.gz

Example that doesn't save or update anything:
zcat sks-dump-0003.pgp.json.gz | python loader.py --dry-run -
python loader.py --dry-run sks-dump-0003.pgp.json
python loader.py --dry-run sks-dump-0003.pgp.json.gz
python loader.py --dry-run *.pgp.json.gz
""")
    parser.add_argument("file", nargs="+", help="the json dump file(s)")
    parser.add_argument("--dry-run", action="store_true", help="don't save anything")
    args = parser.parse_args()

    # read each line sequentially from the list of files
    def rows(filenames):
        for filename in filenames:
            if filename == "-":
                sys.stderr.write(u"File: STDIN\n")
                for line in sys.stdin:
                    yield line
            else:
                for subfilename in glob(filename):
                    sys.stderr.write(u"File: {}\n".format(subfilename))
                    if subfilename.endswith(".gz"):
                        for line in gzip.open(subfilename):
                            yield line
                    else:
                        for line in open(subfilename):
                            yield line

    # load the list of keys from the files or stdin
    results = load_keys_from_json(rows(args.file), dry_run=args.dry_run)
    sys.stderr.write(u"""\
Results for keys{}:
{} saved
{} skipped
{} updated
""".format(
        " (dry_run)" if args.dry_run else "",
        len(results['saved']),
        len(results['skipped']),
        len(results['updated']),
    ))

