"""
This is a script that imports json pgp keys from openpgp-python
dumps into the sks-explorer database.
"""

import json
from base64 import b64decode
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

        # reusable function to extract publickey details
        def _publickey_details(k):

            # set hashes for the full key and the publickey packet
            result = {
                "full_sha512": full_sha512,
                "packet_sha512": pub_sha512,
            }

            # set json values
            result['full_json'] = kjson
            packet_json = dict((i, j) for i, j in k.items() if i != "packets")
            result['packet_json'] = json.dumps(packet_json, sort_keys=True)

            # build the updated search string
            subkeys = []
            userids = []
            for p in k.get("packets", []):
                if p['tag_name'] == "Public-Subkey" and p.get("fingerprint"):
                    subkeys.append(p['fingerprint'])
                elif p['tag_name'] == "User ID" and p.get("user_id"):
                    userids.append(p['user_id'])
            search_string = u"{fingerprint} {subkeys} | {userids}".format(
                fingerprint=k.get("fingerprint", u""),
                subkeys=u" ".join(subkeys),
                userids=u" ".join(userids),
            )
            result.update({"search_string": search_string})

            # build basic public key properties
            # TODO: insert other details (algo, created, n, etc.)
            result['fingerprint'] = k.get("fingerprint", None)
            result['key_id'] = k.get("key_id", None)

            return result

        # reusable function to extract subkey details
        def _subkey_details(p):

            # set hashes for the subkey packet
            result = {
                "packet_sha512": sha512(p['packet_raw'].decode("hex")).hexdigest(),
                "packet_json": json.dumps(p, sort_keys=True),
            }

            # build basic subkey key properties
            # TODO: insert other details (algo, created, n, etc.)
            result['fingerprint'] = p.get("fingerprint", None)
            result['key_id'] = p.get("key_id", None)

            return result

        # reusable function to extract user id details
        def _userid_details(p):
            result = {
                "packet_sha512": sha512(p['packet_raw'].decode("hex")).hexdigest(),
                "packet_json": json.dumps(p, sort_keys=True),
                "user_id": p.get("user_id", None),
            }
            return result

        # function to extract user attribute details from packet dict
        def _userattribute_details(p):
            result = {
                "packet_sha512": sha512(p['packet_raw'].decode("hex")).hexdigest(),
            }
            return result

        # function to extract user attribute details from packet dict
        def _image_details(sp):
            result = {}
            if sp.get("image", None) is not None:
                result['image'] = b64decode(sp['image'])
            return result

        # function to extract signature details from packet dict
        def _signature_details(p):
            result = {
                "packet_sha512": sha512(p['packet_raw'].decode("hex")).hexdigest(),
                "packet_json": json.dumps(p, sort_keys=True),
            }

            # find signer key_id
            if p.get("version", None) is not None:

                # version 3 signature
                if p['version'] == 3:
                    result['signer_key_id'] = p.get("key_id", None)

                # version 4 signature
                elif p['version'] == 4:
                    for sp in p.get("subpackets", []):
                        if sp.get("key_id", None) is not None:
                            result['signer_key_id'] = sp['key_id']

            return result

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
                        while i < len(k['packets']) and k['packets'][i]['tag_name'] == "Signature":
                            sig_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                            new_packets["subkey|{}|{}".format(subkey_sha512, sig_sha512)] = k['packets'][i]
                            i += 1

                    # user id and signatures
                    elif k['packets'][i]['tag_name'] == "User ID":
                        userid_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                        new_packets["userid|{}".format(userid_sha512)] = k['packets'][i]
                        i += 1
                        while i < len(k['packets']) and k['packets'][i]['tag_name'] == "Signature":
                            sig_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                            new_packets["userid|{}|{}".format(userid_sha512, sig_sha512)] = k['packets'][i]
                            i += 1

                    # user attribute and signatures
                    elif k['packets'][i]['tag_name'] == "User Attribute":
                        userattribute_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                        new_packets["userattribute|{}".format(userattribute_sha512)] = k['packets'][i]
                        i += 1
                        while i < len(k['packets']) and k['packets'][i]['tag_name'] == "Signature":
                            sig_sha512 = sha512(k['packets'][i]['packet_raw'].decode("hex")).hexdigest()
                            new_packets["userattribute|{}|{}".format(userattribute_sha512, sig_sha512)] = k['packets'][i]
                            i += 1

                    # unrecognized packet type, so skip
                    else:
                        i += 1

                # add packets that are new
                packets_matching = set(new_packets.keys()).intersection(set(existing_packets.keys()))
                packet_sigs = {
                    #"<subkey_packet_sha512>": {
                    #    "obj": <SubKey_obj>,
                    #    "sigs": {
                    #        "<sig_concat>": <sig_packet_dict>,
                    #        ...
                    #    }
                    #},
                    #...
                }
                for key, p in new_packets.items():
                    segments = key.split("|")

                    # save first layer (subkeys, user ids, user attributes)
                    if key not in packets_matching:

                        # signatures directly on public key
                        if key.startswith("publickey"):
                            new_sig_details = _signature_details(p)
                            new_sig = models.Signature(**new_sig_details)
                            new_sig.publickey = existing_key.id
                            if not dry_run:
                                models.db.session.add(new_sig)
                                models.db.session.commit()

                        # skip packet signatures until first layer is saved
                        elif len(segments) == 3:
                            packet_sigs.setdefault(segments[1], {}).setdefault("sigs", {})[key] = p
                            continue

                        # save new subkey under existing public key
                        elif key.startswith("subkey"):
                            new_subkey_details = _subkey_details(p)
                            new_subkey = models.SubKey(**new_subkey_details)
                            new_subkey.publickey = existing_key.id
                            if not dry_run:
                                models.db.session.add(new_subkey)
                                models.db.session.commit()
                            packet_sigs.setdefault(segments[1], {})['obj'] = new_subkey

                        # save new user id under existing public key
                        elif key.startswith("userid"):
                            new_userid_details = _userid_details(p)
                            new_userid = models.UserID(**new_userid_details)
                            new_userid.publickey = existing_key.id
                            if not dry_run:
                                models.db.session.add(new_userid)
                                models.db.session.commit()
                            packet_sigs.setdefault(segments[1], {})['obj'] = new_userid

                        # save new user attribute under existing public key
                        elif key.startswith("userattribute"):
                            new_userattribute_details = _userattribute_details(p)
                            new_userattribute = models.UserAttribute(**new_userattribute_details)
                            new_userattribute.publickey = existing_key.id
                            if not dry_run:
                                models.db.session.add(new_userattribute)
                                models.db.session.commit()
                            for sp in p.get("subpackets", []):
                                if sp.get("image", None) is not None:
                                    new_image_details = _image_details(sp)
                                    new_image = models.Image(**new_image_details)
                                    new_image.userattribute = new_userattribute.id
                                    if not dry_run:
                                        models.db.session.add(new_image)
                                        models.db.session.commit()
                            packet_sigs.setdefault(segments[1], {})['obj'] = new_userattribute

                    # add reference to sig_packets so that signatures on existing
                    # packets can be saved correctly
                    else:
                        packet_sigs.setdefault(segments[1], {})['obj'] = existing_packets[key]

                # save new signature packets under the first layer
                for sig_ref in packet_sigs.values():
                    for sig_key, sig_dict in sig_ref.get("sigs", {}).items():
                        new_sig_details = _signature_details(sig_dict)
                        new_sig = models.Signature(**new_sig_details)
                        if sig_key.startswith("subkey"):
                            new_sig.subkey = sig_ref['obj'].id
                        elif sig_key.startswith("userid"):
                            new_sig.userid = sig_ref['obj'].id
                        elif sig_key.startswith("userattribute"):
                            new_sig.userattribute = sig_ref['obj'].id
                        if not dry_run:
                            models.db.session.add(new_sig)
                            models.db.session.commit()

                # remove packets that are obsolete
                for key, p in existing_packets.items():
                    if key not in packets_matching:
                        if not dry_run:
                            models.db.session.delete(p)
                            models.db.session.commit()

                # update public key details
                for k, v in _publickey_details(k).items():
                    setattr(existing_key, k, v)

                # save the updated public key
                if not dry_run:
                    models.db.session.add(existing_key)
                    models.db.session.commit()

                results['updated'].append(full_sha512)
                continue

        # the key is not in the database so save it
        else:

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
            new_key_details = _publickey_details(k)
            new_key = models.PublicKey(**new_key_details)

            # save the new key
            if not dry_run:
                models.db.session.add(new_key)
                models.db.session.commit()

            # insert new packets
            i = 0
            while i < len(k.get("packets", [])):

                # signatures directly on the public key
                if k['packets'][i]['tag_name'] == "Signature":
                    new_sig_details = _signature_details(k['packets'][i])
                    new_sig = models.Signature(**new_sig_details)
                    new_sig.publickey = new_key.id
                    if not dry_run:
                        models.db.session.add(new_sig)
                        models.db.session.commit()
                    i += 1

                # subkey and signatures
                elif k['packets'][i]['tag_name'] == "Public-Subkey":
                    new_subkey_details = _subkey_details(k['packets'][i])
                    new_subkey = models.SubKey(**new_subkey_details)
                    new_subkey.publickey = new_key.id
                    if not dry_run:
                        models.db.session.add(new_subkey)
                        models.db.session.commit()
                    i += 1
                    while i < len(k['packets']) and k['packets'][i]['tag_name'] == "Signature":
                        new_sig_details = _signature_details(k['packets'][i])
                        new_sig = models.Signature(**new_sig_details)
                        new_sig.subkey = new_subkey.id
                        if not dry_run:
                            models.db.session.add(new_sig)
                            models.db.session.commit()
                        i += 1

                # user id and signatures
                elif k['packets'][i]['tag_name'] == "User ID":
                    new_userid_details = _userid_details(k['packets'][i])
                    new_userid = models.UserID(**new_userid_details)
                    new_userid.publickey = new_key.id
                    if not dry_run:
                        models.db.session.add(new_userid)
                        models.db.session.commit()
                    i += 1
                    while i < len(k['packets']) and k['packets'][i]['tag_name'] == "Signature":
                        new_sig_details = _signature_details(k['packets'][i])
                        new_sig = models.Signature(**new_sig_details)
                        new_sig.userid = new_userid.id
                        if not dry_run:
                            models.db.session.add(new_sig)
                            models.db.session.commit()
                        i += 1

                # user attribute and signatures
                elif k['packets'][i]['tag_name'] == "User Attribute":
                    new_userattribute_details = _userattribute_details(k['packets'][i])
                    new_userattribute = models.UserAttribute(**new_userattribute_details)
                    new_userattribute.publickey = new_key.id
                    if not dry_run:
                        models.db.session.add(new_userattribute)
                        models.db.session.commit()
                    for sp in k['packets'][i].get("subpackets", []):
                        if sp.get("image", None) is not None:
                            new_image_details = _image_details(sp)
                            new_image = models.Image(**new_image_details)
                            new_image.userattribute = new_userattribute.id
                            if not dry_run:
                                models.db.session.add(new_image)
                                models.db.session.commit()
                    i += 1
                    while i < len(k['packets']) and k['packets'][i]['tag_name'] == "Signature":
                        new_sig_details = _signature_details(k['packets'][i])
                        new_sig = models.Signature(**new_sig_details)
                        new_sig.userattribute = new_userattribute.id
                        if not dry_run:
                            models.db.session.add(new_sig)
                            models.db.session.commit()
                        i += 1

                # unrecognized packet type, so skip
                else:
                    i += 1

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

