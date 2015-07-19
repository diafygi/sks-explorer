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

        # calculate hash of full public key
        k = json.loads(kjson)
        full_raw = k['packet_raw'].decode("hex")
        for p in k.get("packets", []):
            full_raw += p['packet_raw'].decode("hex")
        full_sha512 = sha512(full_raw).hexdigest()

        # skip unchanged full public key packets
        unchanged_keys = models.PublicKey.query.filter_by(full_sha512=full_sha512).all()
        if len(unchanged_keys) > 0:
            results['skipped'].append(full_sha512)
            continue

        # see if there's a public key that needs to be updated
        pub_sha512 = sha512(k['packet_raw'].decode("hex")).hexdigest()
        existing_keys = models.PublicKey.query.filter_by(packet_sha512=pub_sha512).all()

        # update existing keys
        if len(existing_keys) > 0:
            for existing_key in existing_keys:
                """
                This section compares existing packets for public keys
                to the new packets using a reference dictionary with
                concatinated hashes of the packets used as keys. This
                allows for easy comparison of what has changed in the
                full public key so only the changes need to be saved.

                existing_packets = {
                    "userid|<userid_packet_sha512>": <UserID object>,
                    "userid|<userid_packet_sha512>|<signature_packet_sha512>": <Signature object>,
                    ...
                }

                new_packets = {
                    "userid|<userid_packet_sha512>": <packet_json_dict>,
                    "userid|<userid_packet_sha512>|<signature_packet_sha512>": <packet_json_dict>,
                    ...
                }
                """

                # signatures directly on the public key
                existing_packets = {}
                for sig in models.Signature.query.filter_by(publickey=existing_key.id).all():
                    existing_packets["publickeys|{}|{}".format(pub_sha512, sig.packet_sha512)] = sig

                # subkeys and their signatures
                for subkey in models.SubKey.query.filter_by(publickey=existing_key.id).all():
                    existing_packets["subkey|{}".format(subkey.packet_sha512)] = subkey
                    for sig in models.Signature.query.filter_by(subkey=subkey.id).all():
                        existing_packets["subkey|{}|{}".format(subkey.packet_sha512, sig.packet_sha512)] = sig

                # user ids and their signatures
                for userid in models.UserID.query.filter_by(publickey=existing_key.id).all():
                    existing_packets["userid|{}".format(userid.packet_sha512)] = userid
                    for sig in models.Signature.query.filter_by(userid=userid.id).all():
                        existing_packets["userid|{}|{}".format(userid.packet_sha512, sig.packet_sha512)] = sig

                # user attributes and their signatures
                for userattribute in models.UserAttribute.query.filter_by(publickey=existing_key.id).all():
                    existing_packets["userattribute|{}".format(userattribute.packet_sha512)] = userattribute
                    for sig in models.Signature.query.filter_by(userattribute=userattribute.id).all():
                        existing_packets["userattribute|{}|{}".format(userattribute.packet_sha512, sig.packet_sha512)] = sig

                # build new packets reference
                new_packets = {}
                i = 0
                while i < len(k.get("packets", [])):

                    # signatures directly on the public key
                    if k['packets'][i]['tag_name'] == "Signature":
                        sig_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                        new_packets["publickey|{}|{}".format(pub_sha512, sig_sha512)] = k['packets'][i]
                        i += 1

                    # subkey and signatures
                    elif k['packets'][i]['tag_name'] == "Public-Subkey":
                        subkey_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                        new_packets["subkey|{}".format(subkey_sha512)] = k['packets'][i]
                        i += 1
                        while k['packets'][i]['tag_name'] == "Signature":
                            sig_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                            new_packets["subkey|{}|{}".format(subkey_sha512, sig_sha512)] = k['packets'][i]
                            i += 1

                    # user id and signatures
                    elif k['packets'][i]['tag_name'] == "User ID":
                        userid_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                        new_packets["userid|{}".format(userid_sha512)] = k['packets'][i]
                        i += 1
                        while k['packets'][i]['tag_name'] == "Signature":
                            sig_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                            new_packets["userid|{}|{}".format(userid_sha512, sig_sha512)] = k['packets'][i]
                            i += 1

                    # user attribute and signatures
                    elif k['packets'][i]['tag_name'] == "User Attribute":
                        userattribute_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                        new_packets["userattribute|{}".format(userattribute_sha512)] = k['packets'][i]
                        i += 1
                        while k['packets'][i]['tag_name'] == "Signature":
                            sig_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                            new_packets["userattribute|{}|{}".format(userattribute_sha512, sig_sha512)] = k['packets'][i]
                            i += 1

                    # unrecognized packet type, so skip (shouldn't happen)
                    else:
                        i += 1

                # add packets that are new
                packets_matching = set(new_packets.keys()).intersection(set(existing_packets.keys()))
                for key, p in new_packets.items():
                    if key not in packets_matching:
                        # TODO: insert packets
                        pass

                # remove packets that are obsolete
                for key, p in existing_packets.items():
                    if key not in packets_matching:
                        models.db.session.delete(p)
                        models.db.session.commit()

                results['updated'].append(full_sha512)
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
                    full_sha512=full_sha512,
                    packet_sha512=pub_sha512,
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

            results['saved'].append(full_sha512)

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

