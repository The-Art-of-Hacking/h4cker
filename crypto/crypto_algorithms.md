# Cryptographic Algorithms


<table>
<tbody>
<tr>
<th scope="col">Algorithm</th>
<th scope="col">Operation</th>
<th scope="col">Status</th>
<th scope="col">Alternative</th>
<th scope="col">QCR</th>
</tr>
<tr>
<td>DES</td>
<td>Encryption</td>
<td>Avoid</td>
<td>AES</td>
<td>&mdash;</td>
</tr>
<tr>
<td>3DES</td>
<td>Encryption</td>
<td>Legacy</td>
<td>AES</td>
<td>&mdash;</td>
</tr>
<tr>
<td>RC4</td>
<td>Encryption</td>
<td>Avoid</td>
<td>AES</td>
<td>&mdash;</td>
</tr>
<tr>
<td>
<p>AES-CBC mode</p>
<p>AES-GCM mode</p>
</td>
<td>
<p>Encryption</p>
<p>Authenticated encryption</p>
</td>
<td>
<p>Acceptable</p>
<p>NGE</p>
</td>
<td>
<p>AES-GCM</p>
<p>&mdash;</p>
</td>
<td>
<p>✓ (256-bit)</p>
<p>✓ (256-bit)</p>
</td>
</tr>
<tr>
<td>
<p>DH-768, -1024</p>
<p>RSA-768, -1024</p>
DSA-768, -1024</td>
<td>
<p>Key exchange</p>
<p>Encryption</p>
<p>Authentication</p>
</td>
<td>
<p>Avoid</p>
</td>
<td>
<p>DH-3072 (Group 15)</p>
<p>RSA-3072</p>
DSA-3072</td>
<td>
<p>&mdash;</p>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
</tr>
<tr>
<td>
<p>DH-2048</p>
<p>RSA-2048</p>
DSA-2048</td>
<td>
<p>Key exchange</p>
<p>Encryption</p>
<p>Authentication</p>
</td>
<td>
<p>Acceptable</p>
</td>
<td>
<p>ECDH-256</p>
<p>&mdash;</p>
ECDSA-256</td>
<td>
<p>&mdash;</p>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
</tr>
<tr>
<td>
<p>DH-3072</p>
<p>RSA-3072</p>
<p>DSA-3072</p>
</td>
<td>
<p>Key exchange</p>
<p>Encryption</p>
<p>Authentication</p>
</td>
<td>Acceptable</td>
<td>
<p>ECDH-256</p>
<p>&mdash;</p>
ECDSA-256</td>
<td>
<p>&mdash;</p>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
</tr>
<tr>
<td>MD5</td>
<td>Integrity</td>
<td>Avoid</td>
<td>SHA-256</td>
<td>&mdash;</td>
</tr>
<tr>
<td>
<p>SHA-1</p>
</td>
<td>
<p>Integrity</p>
</td>
<td>
<p>Legacy</p>
</td>
<td>
<p>SHA-256</p>
</td>
<td>&mdash;</td>
</tr>
<tr>
<td>
<p>SHA-256</p>
<p>SHA-384</p>
<p>SHA-512</p>
</td>
<td>
<p>Integrity</p>
</td>
<td>
<p>NGE</p>
</td>
<td>
<p>SHA-384</p>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
<td>
<p>&mdash;</p>
<p>✓</p>
<p>✓</p>
</td>
</tr>
<tr>
<td>HMAC-MD5</td>
<td>Integrity</td>
<td>Legacy</td>
<td>HMAC-SHA-256</td>
<td>&mdash;</td>
</tr>
<tr>
<td>HMAC-SHA-1</td>
<td>Integrity</td>
<td>Acceptable</td>
<td>HMAC-SHA-256</td>
<td>&mdash;</td>
</tr>
<tr>
<td>HMAC-SHA-256</td>
<td>Integrity</td>
<td>NGE</td>
<td>&mdash;</td>
<td>✓</td>
</tr>
<tr>
<td>
<p>ECDH-256</p>
ECDSA-256</td>
<td>
<p>Key exchange</p>
<p>Authentication</p>
</td>
<td>
<p>Acceptable</p>
</td>
<td>
<p>ECDH-384</p>
ECDSA-384</td>
<td>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
</tr>
<tr>
<td>
<p>ECDH-384</p>
ECDSA-384</td>
<td>
<p>Key exchange</p>
<p>Authentication</p>
</td>
<td>
<p>NGE</p>
</td>
<td>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
<td>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
</tr>
<tr>
<td colspan="5"><a name="ftn1"></a>
<p>1. QCR = quantum computer resistant.</p>
<a name="ftn2"></a>
<p>2. NGE = next generation encryption.</p>
</td>
</tr>
</tbody>
</table>


- Avoid: Algorithms that are marked as Avoid do not provide adequate security against modern threats and should not be used to protect sensitive information. It is recommended that these algorithms be replaced with stronger algorithms.

- Legacy: Legacy algorithms provide a marginal but acceptable security level. They should be used only when no better alternatives are available, such as when interoperating with legacy equipment. It is recommended that these legacy algorithms be phased out and replaced with stronger algorithms.

- Acceptable: Acceptable algorithms provide adequate security.

- Next generation encryption (NGE): NGE algorithms are expected to meet the security and scalability requirements of the next two decades. For more information, see Next Generation Encryption.

- Quantum computer resistant (QCR): There's a lot of research around quantum computers (QCs) and their potential impact on current cryptography standards. Although practical QCs would pose a threat to crypto standards for public-key infrastructure (PKI) key exchange and encryption, no one has demonstrated a practical quantum computer yet. It is an area of active research and growing interest. Although it is possible, it can't be said with certainty whether practical QCs will be built in the future. An algorithm that would be secure even after a QC is built is said to have postquantum security or be quantum computer resistant (QCR). AES-256, SHA-384, and SHA-512 are believed to have postquantum security. There are public key algorithms that are believed to have postquantum security too, but there are no standards for their use in Internet protocols yet.

## Additional References
- NIST Post-Quantum Cryptography Project: https://csrc.nist.gov/projects/post-quantum-cryptography
- Post Quantum Cryptography (Wikipedia): https://en.wikipedia.org/wiki/Post-quantum_cryptography
