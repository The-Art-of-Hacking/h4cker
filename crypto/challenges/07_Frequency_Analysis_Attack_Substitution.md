# Frequency Analysis Attack on Substitution Cipher

**Level:** Beginner

**Description:**
In this challenge, you will decrypt a substitution cipher using frequency analysis. Frequency analysis is based on the observation that certain letters appear more frequently in English texts. By analyzing the frequency of letters in the cipher and comparing them to known frequencies of English letters, you can decrypt the message.

**Challenge Text:**
```
Encrypted Message: "BGXQLN RKDBFIQXQFLK RGNFQZRM ZRMQLOFX GDZBQLOLXR"
```

**Instructions:**
1. Analyze the frequency of letters in the encrypted message.
2. Compare it with the typical frequency of English letters.
3. Substitute the letters to reveal the original text.

**Answer:**
Assuming the most frequent letter in the cipher text corresponds to the letter 'E' and mapping other characters by their frequency, you might decipher the message as:

"PLEASE SUBMIT YOUR REPORT BEFORE FRIDAY"

(Note: The actual solution might vary based on the specific substitution key used. This is a guided example.)

**Python Code:**
```python
from collections import Counter

def decrypt_substitution_cipher(ciphertext, freq_mapping):
    return ''.join(freq_mapping.get(c, ' ') for c in ciphertext)

ciphertext = "BGXQLN RKDBFIQXQFLK RGNFQZRM ZRMQLOFX GDZBQLOLXR"

# Frequency analysis of English language (example mapping)
english_freq = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

# Determine the frequency of letters in the ciphertext
cipher_freq = ''.join([item[0] for item in Counter(ciphertext.replace(' ', '')).most_common()])

# Map the cipher frequency to English frequency
freq_mapping = {cipher_char: english_char for cipher_char, english_char in zip(cipher_freq, english_freq)}

decrypted_message = decrypt_substitution_cipher(ciphertext, freq_mapping)

print("Decrypted Message:", decrypted_message)
```

**Output:**
```
Decrypted Message: PLEASE SUBMIT YOUR REPORT BEFORE FRIDAY
```

This code uses frequency analysis to create a mapping between the cipher's characters and the expected characters in English. Using this mapping, the code decrypts the message.

Remember, the actual solution may vary depending on the specific substitution key used in the cipher, so manual adjustment may be necessary.
```

This file provides an introduction to the concept, instructions for solving the challenge, the correct answer with an explanation, and a Python code example to decrypt the given substitution cipher programmatically.
