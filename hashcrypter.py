import hashlib
import argparse
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor

def crack_hash_parallel(hash_value, wordlist_path, hash_algorithm):
    hash_functions = {
        'md5' : hashlib.md5,
        'sha1' : hashlib.sha1,
        'sha256' : hashlib.sha256,
        'sha384' : hashlib.sha384,
        'sha512' : hashlib.sha512
    }

    if hash_algorithm not in hash_functions:
        sys.exit("Hash algorithm not supported !\n")

    hash_func = hash_functions[hash_algorithm]

    with open(wordlist_path,"r") as f:
        with ThreadPoolExecutor() as executor:
            futures = []
            for line in f:
                password = line.strip()
                futures.append(executor.submit(try_password, password, hash_value, hash_func))

            for future in futures:
                result = future.result()
                if result:
                    return result
    return None

def try_password(password, hash_value, hash_func):
    hashed_password = hash_func(password.encode()).hexdigest()
    if hashed_password == hash_value:
        return password
    return None

if __name__ == '__main__':
    print(r"""
    C|R|A|C|K|   Y|O|U|R|   H|A|S|H|
""")

    start_time = time.time()

    parser = argparse.ArgumentParser(description="Hash Cracking Tool",add_help=True)
    parser.add_argument('-a','--algorithm',type=str,help="Hash algorithm (md5, sha1, sha256, sha384, sha512",required=True)
    parser.add_argument('-w','--wordlist',type=str,help="Path to the wordlist file", required=True)
    parser.add_argument('-H', '--hash', type=str, help="Hash value to crack", required=True)

    args = parser.parse_args()

    hash_algorithm = args.algorithm.lower()
    wordlist_path = args.wordlist
    hash_value = args.hash

    if not os.path.isfile(wordlist_path):
        sys.exit("Wordlist file not found !\n")

    if not os.access(wordlist_path, os.R_OK):
        sys.exit("Wordlist file is not readable !\n")

    cracked_password = crack_hash_parallel(hash_value,wordlist_path,hash_algorithm)

    if cracked_password:
        print(f"Cracked! Hash: {hash_value} Password: {cracked_password}\n")
    else:
        print("Hash not cracked\n")

    end_time = time.time()
    elapsed_time = end_time - start_time
    print(f"Elapsed time: {elapsed_time} seconds")
    