# Homomorphic Encryption

Homomorphic encryption is a form of encryption allowing one to perform calculations on encrypted data without decrypting it first. The result of the computation is in encrypted form, and when decrypted, it matches the result of the operation as if it had been performed on the plain text.

This method is beneficial for privacy-preserving computations on sensitive data. It is especially useful for cloud computing, where you can process your data on third-party servers without revealing any sensitive information to those servers.

Although promising, homomorphic encryption is computationally intensive and not yet practical for all applications. Researchers are working on improving the efficiency of these methods, and we can expect their usage to increase in the future.

The following is a simple example of addition and multiplication operations using homomorphic encryption with Python and a library called Pyfhel, which stands for Python for Fully Homomorphic Encryption Libraries. In this example, we will encrypt two integers, perform addition and multiplication operations on the encrypted data, and then decrypt the results.

Install the Pyfhel library:

```python
pip install Pyfhel
```

Here is the simple Python code:

```python
from Pyfhel import Pyfhel, PyCtxt

# Create a Pyfhel object
HE = Pyfhel()

# Generate a public and secret key
HE.keyGen()

# Encrypt two numbers
num1 = 5
num2 = 10
enc_num1 = HE.encryptInt(num1)
enc_num2 = HE.encryptInt(num2)

# Perform addition operation on encrypted numbers
enc_result_add = enc_num1 + enc_num2

# Perform multiplication operation on encrypted numbers
enc_result_mul = enc_num1 * enc_num2

# Decrypt the results
result_add = HE.decryptInt(enc_result_add)
result_mul = HE.decryptInt(enc_result_mul)

print(f"Decrypted addition result: {result_add}, Expected: {num1+num2}")
print(f"Decrypted multiplication result: {result_mul}, Expected: {num1*num2}")
```

This script creates an instance of `Pyfhel`, generates a public and secret key with `keyGen()`, encrypts two integers using `encryptInt()`, adds and multiplies them, then decrypts the results using `decryptInt()`. The decrypted results should be equal to the results of adding and multiplying the original, unencrypted numbers.

Remember that this is a simplified example. In a real-world scenario, key management and ensuring the security of the encryption and decryption operations are crucial and more complex. Furthermore, full homomorphic encryption is a computationally intensive task and may not be suitable for all types of data or applications. 
