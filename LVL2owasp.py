import requests
import re
import math

# Prompt the user to enter the website URL
url = input("Enter full website URL including http:// ")

# Crawl the website and extract hashes, passwords, crypto algorithms, and check for encryption enforcement
def crawl_website(url):
    res = requests.get(url)

    pattern = r"\b([A-Fa-f0-9]{32,128}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128})\b"
    hashes = sorted(set(match.group(0) for match in re.finditer(pattern, res.text)))

    pattern = r"(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*[\!\@\#\$\%\^\&\*\(\)\_\+\-\{\}\[\]\|\:\;\"\'\<\>\?\,\.\/\~])(?=\S{8,})"
    passwords = sorted(set(match.group(0) for match in re.finditer(pattern, res.text)))

    pattern = r"\b(sha1|sha224|sha256|sha384|sha512|md5|blake2b|blake2s)\b"
    crypto_algorithms = sorted(set(match.group(0) for match in re.finditer(pattern, res.text)))

    has_sufficient_entropy = len(hashes) >= 10 and all(len(password) > 0 and len(password) >= math.log(len(password), 2) for password in passwords)
    has_encryption_enforcement = "Strict-Transport-Security" in res.headers
    has_caching_enabled = "Cache-Control" in res.headers

    return hashes, passwords, crypto_algorithms, has_sufficient_entropy, has_encryption_enforcement, has_caching_enabled

def print_and_save_results(hashes, passwords, crypto_algorithms, has_sufficient_entropy, has_encryption_enforcement, has_caching_enabled):
    print("\n[+] Found Hashes:")
    for hash_value in hashes:
        hash_type = ''
        if len(hash_value) == 32:
            hash_type = 'MD5'
        elif len(hash_value) == 40:
            hash_type = 'SHA1'
        elif len(hash_value) == 64:
            hash_type = 'SHA256'
        elif len(hash_value) == 96:
            hash_type = 'SHA384'
        elif len(hash_value) == 128:
            hash_type = 'SHA512'
        print(f"{hash_value} ({hash_type})")

    print("\n[+] Found Passwords:")
    password_set = set(password for password in passwords if re.match(r"(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*[\!\@\#\$\%\^\&\*\(\)\_\<\>\?\,\.\/\~])(?=\S{8,16}$)\S+", password))    
    for password in sorted(password_set):
        print(password)

    print("\n[+] Found Crypto Algorithms:")
    for algorithm in crypto_algorithms:
        print(algorithm)

    print(f"\n[+] Has Sufficient Entropy: {has_sufficient_entropy}")
    print(f"\n[+] Has Encryption Enforcement: {has_encryption_enforcement}")
    print(f"\n[+] Has Caching Enabled: {has_caching_enabled}")

    save_to_file = input("\nWould you like to save the results to a file? (y/n) ")
    if save_to_file.lower() == "y":
        filename = input("Enter the filename to save the results to: ")
        with open(filename, "w") as file:
            file.write("[+] Found Hashes:\n")
            for hash_value in hashes:
                hash_type = ''
                if len(hash_value) == 32:
                    hash_type = 'MD5'
                elif len(hash_value) == 40:
                    hash_type = 'SHA1'
                elif len(hash_value) == 64:
                    hash_type = 'SHA256'
                elif len(hash_value) == 96:
                    hash_type = 'SHA384'
                elif len(hash_value) == 128:
                    hash_type = 'SHA512'
                file.write(f"{hash_value} ({hash_type})\n")

            file.write("\n[+] Found Passwords:\n")
            pattern = r"(?=\S*[a-z])(?=\S*[A-Z])(?=\S*\d)(?=\S*[\!\@\#\$\%\^\&\*\(\)\_\<\>\?\,\.\/\~])(?=\S{8,16}$)\S+"
            password_set = set(password for password in passwords if re.match(pattern, password))
            for password in sorted(password_set):
                file.write(password + "\n")

            file.write("\n[+] Found Crypto Algorithms:\n")
            for algorithm in crypto_algorithms:
                file.write(algorithm + "\n")

            file.write(f"\n[+] Has Sufficient Entropy: {has_sufficient_entropy}")

            file.write(f"\n[+] Has Encryption Enforcement: {has_encryption_enforcement}")

            file.write(f"\n[+] Has Caching Enabled: {has_caching_enabled}")

        print(f"Results saved to {filename}")

# Crawl the website and print and save the results
hashes, passwords, crypto_algorithms, has_sufficient_entropy, has_encryption_enforcement, has_caching_enabled = crawl_website(url)
print_and_save_results(hashes, passwords, crypto_algorithms, has_sufficient_entropy, has_encryption_enforcement, has_caching_enabled)
