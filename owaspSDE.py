import requests
import re
import hashlib
from collections import Counter
from bs4 import BeautifulSoup

def crawl_website(url):
    response = requests.get(url)
    hashes = set()  # Use a set to store unique hashes
    # Use regular expression to search for hashes in the response content
    hash_patterns = {
        'MD5': r"\b[A-Fa-f0-9]{32}\b",
        'SHA1': r"\b[A-Fa-f0-9]{40}\b",
        'RIPEMD160': r"\b[A-Fa-f0-9]{40}\b",
        'Whirlpool': r"\b[A-Fa-f0-9]{128}\b",
        'SHA256': r"\b[A-Fa-f0-9]{64}\b",
        'SHA512': r"\b[A-Fa-f0-9]{128}\b"
    }
    for hash_type, pattern in hash_patterns.items():
        matches = re.findall(pattern, response.text)
        if matches:
            for match in matches:
                hash_object = hashlib.new(hash_type.lower())
                hash_object.update(match.encode('utf-8'))
                hash_value = hash_object.hexdigest()
                hashes.add(f"{hash_type}: {hash_value}")  # Add only unique hashes to the set
    
    # Use BeautifulSoup to parse the HTML
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all instances of hard-coded passwords
    password_tags = soup.find_all(string=re.compile("password"))
    passwords = []
    for tag in password_tags:
        if "type" in tag.parent.attrs and tag.parent.attrs["type"] == "password":
            passwords.append(tag)

    # Find all instances of risky crypto algorithms
    crypto_algorithms = []
    for tag in soup.find_all(string=re.compile("(MD5|SHA1|DES|RC4)")):
        if tag.parent.name in ["script", "style"]:
            continue
        crypto_algorithms.append(tag)

    # Check the entropy of the website's text
    text = soup.get_text()

    # Count the occurrence of each character in the website's text
    char_counts = Counter(text)

    # Calculate the entropy of the website's text
    total_chars = len(text)
    entropy = sum(count / total_chars * (total_chars / float(count)) for count in char_counts.values())

    # Determine if the entropy is sufficient
    has_sufficient_entropy = entropy > 3

    return hashes, passwords, crypto_algorithms, has_sufficient_entropy

if __name__ == '__main__':
    url = input("Enter the website URL to crawl: ")
    hashes, passwords, crypto_algorithms, has_sufficient_entropy = crawl_website(url)

    if len(hashes) > 0:
        print(f"Found {len(hashes)} unique hashes on {url}:")
        for i, hash in enumerate(hashes):
            print(f"{i+1}. {hash}")
        save_option = input("Do you want to save the output to a file? (y/n)")
        if save_option == 'y':
            file_name = input("Enter the file name: ")
            with open(file_name, 'w') as file:
                for i, hash in enumerate(hashes):
                    file.write(f"{i+1}. {hash}\n")
            print(f"Output saved to {file_name}.")
    else:
        print(f"No hashes found on {url}.")
    
    # Print the results
    print(f"Hard-coded passwords found: {len(passwords)}")
    print(f"Risky crypto algorithms found: {len(crypto_algorithms)}")
    print(f"Has sufficient entropy: {has_sufficient_entropy}")
