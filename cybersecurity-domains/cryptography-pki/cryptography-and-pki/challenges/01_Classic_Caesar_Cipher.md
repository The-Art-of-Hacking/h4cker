# Challenge 1: Caesar Cipher Shift

**Challenge Text:**
```
Sifnz ebjnt, zpv ibwf cffo difdlfe! Dpvme zpv efdszqujpo uijt tfdsfu nfttbhf?
```

**Instructions:**
1. Analyze the frequency of the letters, or use a brute-force approach to find the shift value.
2. Write a program or manually shift the letters to decrypt the message, applying the reverse shift.
3. Provide the original text.

### Answer:

The Caesar cipher is a type of substitution cipher in which each character in the plaintext is 'shifted' a certain number of places down or up the alphabet. In this particular case, the shift value is 1.

**Decrypted Text:**
```
Rhemy dakim, you have been checked! Could you decrypting this secret message?
```

You can also use these code examples in Python to decrypt the message:

```python
def decrypt_caesar(ciphertext, shift):
    decrypted = ""
    for char in ciphertext:
        if char.isalpha():
            shifted = ord(char) - shift
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
            decrypted += chr(shifted)
        else:
            decrypted += char
    return decrypted

ciphertext = "Sifnz ebjnt, zpv ibwf cffo difdlfe! Dpvme zpv efdszqujpo uijt tfdsfu nfttbhf?"
shift = 1
decrypted_text = decrypt_caesar(ciphertext, shift)
print(decrypted_text)
```

This challenge serves as a fun and educational introduction to the field of cryptography, allowing you to explore basic decryption techniques. Try the next challenge.
