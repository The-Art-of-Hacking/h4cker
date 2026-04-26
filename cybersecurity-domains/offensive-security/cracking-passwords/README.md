# Understanding Password Cracking

Password cracking involves attempting to discover or guess a user’s password by using various methods and tools. Passwords are often the first line of defense for any system, and cracking them can give unauthorized access if not properly protected.

## Techniques for Password Cracking

1. **Brute Force Attack**: This method involves trying every possible combination of characters until the correct one is found. While thorough, it is also time-consuming and computationally expensive, especially for complex passwords.

2. **Dictionary Attack**: Instead of trying all possible combinations, a dictionary attack uses a list of likely passwords. This list can include common passwords, variations, and even phrases. It’s faster than brute force but relies on the password being in the list.

3. **Rainbow Tables**: These are precomputed tables used to reverse cryptographic hash functions. They significantly speed up the cracking process by storing common hashes and their corresponding plaintext passwords. However, their effectiveness can be mitigated by using salted hashes.

4. **Hybrid Attacks**: Combining dictionary and brute force techniques, hybrid attacks start with dictionary words and then apply variations, such as adding numbers or symbols, to those words.

5. **Password Cracking Tools**: Several tools are available to assist in password cracking. 
   - **John the Ripper**: A popular tool that supports various encryption algorithms and hash types. It’s effective for both brute force and dictionary attacks.
   - **Hashcat**: Known for its speed and support for a wide range of hash algorithms. It can use GPU acceleration to significantly speed up cracking attempts.
   - **NullSec Tools**: Includes hash cracking utilities written in Rust for high-performance password analysis and dictionary management.

In this directory/folder I also included several examples of password cracking using these tools.
