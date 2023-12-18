# SMTP Authentication, Encryption, and DKIM
- SMTP (Simple Mail Transfer Protocol) is the standard protocol for sending emails across the Internet.
- It has mechanisms for both authentication and encryption to enhance security, and DKIM (DomainKeys Identified Mail) is an additional layer of email security. 

### SMTP Authentication

SMTP Authentication is a process that allows a client to log into an SMTP server to send email by providing a username and password. This process ensures that the email sender is authorized to use the server. There are several methods for SMTP authentication, such as:

1. **PLAIN**: Sends username and password in clear text (can be secure if used with SSL/TLS).
2. **LOGIN**: Similar to PLAIN but sends username and password as base64 encoded strings.
3. **CRAM-MD5**: A more secure method where the server sends a unique challenge string and the client responds with a hash of the username, password, and challenge.

### SMTP Encryption

SMTP servers use encryption to secure email contents during transmission. Two common methods are:

1. **STARTTLS**: This command upgrades a plain text connection to an encrypted connection using TLS (Transport Layer Security). It's not a separate protocol but a way to secure existing SMTP connections.
2. **SSL/TLS**: A direct method where the connection starts as encrypted using SSL/TLS. It's often used on different ports (like 465 for SMTPS).

### DKIM (DomainKeys Identified Mail)

DKIM is an email authentication method designed to detect email spoofing. It allows the sender to claim responsibility for a message in a way that can be validated by the recipient. Here's how it works:

1. **Digital Signature**: The sending mail server attaches a unique DKIM signature header to the email. This signature is created using a private key only known to the sender's domain.
2. **Public Key**: The sender's DNS records include a public key that corresponds to the private key used for signing emails.
3. **Verification**: When receiving an email, the recipient's server checks the DKIM signature by retrieving the sender's public key from DNS. It then verifies if the email was indeed signed by the domain's private key.

By using DKIM, email providers can verify that an email was not tampered with and actually comes from the domain it claims to be from. This helps in fighting against phishing and email spoofing.

### DKIM Signature Process

1. **Private Key Signing**:
   - The sending server has a private key, unique to the domain.
   - When an email is sent, this server generates a digital signature of the message's header and body. This signature is based on a cryptographic hash function.
   - The hash is then encrypted with the domain's private key, creating the DKIM signature.
   - This signature is added to the email headers as a field named `DKIM-Signature`.

2. **DKIM-Signature Header**: A typical `DKIM-Signature` header might look like this:
   ```
   DKIM-Signature: v=1; a=rsa-sha256; d=websploit.org; s=selector;
   c=relaxed/relaxed; q=dns/txt; h=from:to:subject:date:message-id;
   bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
   b=dzdVyOfAKCdLXdJOc9G2q8LoXHBQ4PpcgfqPEKgGuhGfQ2Th7euTxA6AxEZJ8uTu
   T9AmdZf/Lb8yX0pGzJhF0X+R7y2NGvZhbqPoeIU4x3mU=;
   ```

   - **v=1**: DKIM version
   - **a=rsa-sha256**: Signing algorithm (RSA with SHA-256)
   - **d=example.com**: Signing domain
   - **s=selector**: Selector used for querying the public key
   - **c=relaxed/relaxed**: Canonicalization algorithm for header and body
   - **q=dns/txt**: Query method for retrieving DKIM key
   - **h=from:to:subject:date:message-id**: List of headers that were signed
   - **bh=...**: Hash of the body
   - **b=...**: The DKIM signature (encrypted hash)

### DKIM Verification Process

1. **Extracting the DKIM Signature**:
   - The receiving server extracts the DKIM signature from the email's headers.

2. **Querying the Public Key**:
   - The server uses the domain (`d=example.com`) and the selector (`s=selector`) to construct a DNS query.
   - The query might look like `selector._domainkey.example.com`.
   - This DNS query returns the public key used by the domain for DKIM signing.

3. **Decrypting the Signature**:
   - Using the retrieved public key, the server decrypts the signature `b=...`, turning it back into a hash.

4. **Re-Hashing and Comparing**:
   - The server then re-computes the hash of the received email's headers and body (as specified in the `h=` and `bh=` fields) using the same hash function.
   - It compares this newly computed hash against the decrypted signature.
   - If they match, it confirms that the email was indeed sent by the domain and has not been altered during transit.

