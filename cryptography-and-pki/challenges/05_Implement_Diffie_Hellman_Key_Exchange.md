# Challenge 5: Implement Diffie-Hellman Key Exchange

**Level:** Intermediate

**Description:**
Simulate the Diffie-Hellman key exchange algorithm to securely share a symmetric key between two parties.

**Challenge Text:**
```
Given prime p = 23, base g = 5
Party A's private key: 6
Party B's private key: 15
```

**Instructions:**
1. Compute Party A's and Party B's public keys.
2. Compute the shared secret key for both parties.
3. Validate that both parties have the same shared secret key.


**Answer:**
Shared secret key: 2

**Code:**
```python
p = 23
g = 5
a_private = 6
b_private = 15

# Compute public keys
A_public = (g ** a_private) % p
B_public = (g ** b_private) % p

# Compute shared secret key
shared_secret_A = (B_public ** a_private) % p
shared_secret_B = (A_public ** b_private) % p

print("Shared secret key (Party A):", shared_secret_A)
print("Shared secret key (Party B):", shared_secret_B)
```

