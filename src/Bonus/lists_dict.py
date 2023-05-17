"""
DDoS Laboratory
Assignment of `Cyber Lab - Defense` course at Ariel-University.

this file contains the implementation for bonus lab.

:since: 17/05/2023
:authors: Lior Vinman & Yoad Tamar
"""

import random
import hashlib
import string
import time

UPPER_BOUND = 1000000


def random_word(length=5):
    """
    this function generates a single random 5-char word
    :param length: length of word to be generated (default: 5)
    :return: random 5-char length word
    """
    chars = string.ascii_uppercase + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


def main():
    words = []  # list for words
    hashes = []  # list for sha256
    w_h = {}  # dictionary of: <word, sha256>

    # filling the lists and the dict
    for i in range(UPPER_BOUND):
        rw = random_word()

        sha256_hash = hashlib.sha256()
        sha256_hash.update(rw.encode())
        hash_hex = sha256_hash.hexdigest()

        words.append(rw)
        hashes.append(hash_hex)

        w_h[rw] = hash_hex

    # opening results files, then accessing hash in list and dict (using O(1) methods)
    with open("bonus_list_p.txt", "w") as f1, open("bonus_dict_p.txt", "w") as f2:
        for i in range(5):
            index = random.randint(0, UPPER_BOUND)

            word_index = words[index]

            sha256_hash = hashlib.sha256()
            sha256_hash.update(word_index.encode())
            hash_hex = sha256_hash.hexdigest()

            start = time.time()
            res = hashes[index]
            end = time.time()
            f1.write(f"{i} {end - start}\n")

            start = time.time()
            res = w_h[words[index]]
            end = time.time()
            f2.write(f"{i} {end - start}\n")


if __name__ == "__main__":
    main()
