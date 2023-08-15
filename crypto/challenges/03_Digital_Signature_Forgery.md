# Challenge 3: Hash Collision Challenge

**Challenge Text:**
```
Find two different inputs that produce the first 24 bits of SHA-256 hash collision.
```

**Instructions:**
1. Understand the properties of the SHA-256 hash function.
2. Implement a chosen collision-finding algorithm, such as the birthday attack.
3. Provide two different inputs that create the same truncated hash value.

### Answer:

Given the complexity of SHA-256, finding collisions is non-trivial. However, we can simplify the task by only considering the first 24 bits of the hash. This reduces the search space, making the task more manageable for a classroom exercise.

The following is a code example to find two different inputs that produce the same first 24 bits of a SHA-256 hash:

```python
import hashlib
from random import randint

def hash_collision(bits=24):
    hash_dict = {}
    mask = (1 << bits) - 1

    while True:
        # Generate a random number and convert it to bytes
        random_number = randint(0, 2**32 - 1)
        input_bytes = random_number.to_bytes(4, 'big')

        # Compute the SHA-256 hash and truncate to the desired number of bits
        hash_full = hashlib.sha256(input_bytes).digest()
        hash_truncated = int.from_bytes(hash_full, 'big') & mask

        # Check for a collision
        if hash_truncated in hash_dict:
            first_collision_input = hash_dict[hash_truncated]
            if first_collision_input != input_bytes: # Ensure they are different inputs
                return (first_collision_input, input_bytes)
        else:
            hash_dict[hash_truncated] = input_bytes

collision_pair = hash_collision()
print(f"Input 1: {int.from_bytes(collision_pair[0], 'big')}")
print(f"Input 2: {int.from_bytes(collision_pair[1], 'big')}")
```

Please note that this code might take some time to execute, depending on the number of bits chosen for the collision and the machine's processing power.

**Explanation:**

1. **Understanding the SHA-256 Hash Function:** This challenge requires familiarity with cryptographic hash functions, particularly SHA-256, and their properties.
   
2. **Implementing the Birthday Attack:** This code snippet implements a simple version of the birthday attack by looking for collisions in the truncated hash. This method leverages the birthday paradox, where the probability of two or more people sharing the same birthday increases surprisingly fast with the number of people.

3. **Finding Two Different Inputs:** The code generates random numbers, hashes them, and checks for collisions in the truncated hash.

This challenge serves as a practical exercise in understanding the properties of cryptographic hash functions and the complexities involved in finding collisions, even when considering only a small portion of the hash. It provides a real-world example of why full hash functions with sufficient bit lengths are essential for security.
