# Cryptographic Algorithms

<table>
<tbody>
<tr>
<th scope="col">Algorithm</th>
<th scope="col">Operation</th>
<th scope="col">Status</th>
<th scope="col">Alternative</th>
<th scope="col">QCR<a href="https://www.cisco.com/c/en/us/about/security-center/next-generation-cryptography.html#ftn1"><sup>1</sup></a></th>
<th scope="col">Mitigation</th>
</tr>
<tr>
<td>DES</td>
<td>Encryption</td>
<td>Avoid</td>
<td>AES</td>
<td>&mdash;</td>
<td>&mdash;</td>
</tr>
<tr>
<td>3DES</td>
<td>Encryption</td>
<td>Legacy</td>
<td>AES</td>
<td>&mdash;</td>
<td>Short key lifetime</td>
</tr>
<tr>
<td>RC4</td>
<td>Encryption</td>
<td>Avoid</td>
<td>AES</td>
<td>&mdash;</td>
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
<p>NGE<a href="https://www.cisco.com/c/en/us/about/security-center/next-generation-cryptography.html#ftn2"><sup>2</sup></a></p>
</td>
<td>
<p>AES-GCM</p>
<p>&mdash;</p>
</td>
<td>
<p>✓ (256-bit)</p>
<p>✓ (256-bit)</p>
</td>
<td>
<p>&mdash;</p>
<p>&mdash;</p>
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
<td>
<p>&mdash;</p>
</td>
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
<td>
<p>&mdash;</p>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
</tr>
<tr>
<td>HMAC-MD5</td>
<td>Integrity</td>
<td>Legacy</td>
<td>HMAC-SHA-256</td>
<td>&mdash;</td>
<td>Short key lifetime</td>
</tr>
<tr>
<td>HMAC-SHA-1</td>
<td>Integrity</td>
<td>Acceptable</td>
<td>HMAC-SHA-256</td>
<td>&mdash;</td>
<td>&mdash;</td>
</tr>
<tr>
<td>HMAC-SHA-256</td>
<td>Integrity</td>
<td>NGE</td>
<td>&mdash;</td>
<td>✓</td>
<td>&mdash;</td>
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
<td>
<p>&mdash;</p>
<p>&mdash;</p>
</td>
</tr>
<tr>
<td colspan="6"><a name="ftn1"></a>
<p>1. QCR = quantum computer resistant.</p>
<a name="ftn2"></a>
<p>2. NGE = next generation encryption.</p>
</td>
</tr>
</tbody>
</table>
