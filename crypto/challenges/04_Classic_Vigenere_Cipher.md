# Challenge 4: Classic Vigenère Cipher

**Level:** Beginner

**Description:**
Crack a message encrypted using the Vigenère cipher with a known keyword.

**Challenge Text:**
```
Encrypted Message: "XBGXLTVJZTFKTRDCXWPNCRTGDHDDJQKFTZR"
Keyword: "KEYWORD"
```

**Instructions:**
1. Utilize the given keyword to decrypt the Vigenère cipher.
2. Provide the original plaintext.


**Answer:**
The decrypted message is "WELCOMETOTHEWORLDOFCRYPTOGRAPHY"

**Code:**
```python
def decrypt_vigenere(ciphertext, keyword):
    keyword_repeated = (keyword * (len(ciphertext) // len(keyword))) + keyword[:len(ciphertext) % len(keyword)]
    decrypted_text = ''
    for i in range(len(ciphertext)):
        decrypted_char = chr(((ord(ciphertext[i]) - ord(keyword_repeated[i])) % 26) + ord('A'))
        decrypted_text += decrypted_char
    return decrypted_text

ciphertext = "XBGXLTVJZTFKTRDCXWPNCRTGDHDDJQKFTZR"
keyword = "KEYWORD"
decrypted_text = decrypt_vigenere(ciphertext, keyword)
print(decrypted_text)
```
