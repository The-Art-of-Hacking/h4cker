Heavy computation(400)
Question:
A friend of mine handed me this script and challenged me to recover the flag. However, I started running it on my school cluster and everything is burning now... Help me please!

Given files:
encrypt.py
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from secret import password, flag
from hashlib import sha256

NB_ITERATIONS = 10871177237854734092489348927
e = 65538

#Old N : N = 16725961734830292192130856503318846470372809633859943564170796604233648911148664645199314305393113642834320744397102098813353759076302959550707448148205851497665038807780166936471173111197092391395808381534728287101705

N = 14968794114523720195251887716913440457986979987674770429103169854116498198112478103466085455257317270930523061714030307370028304505577267672733143013124254253285088080041831478700041394909740024011681885623055622400205


def derive_key(password):
    start = bytes_to_long(password)

    #Making sure I am safe from offline bruteforce attack

    for i in range(NB_ITERATIONS):
        start = start ** e
        start %= N

    #We are never too cautious let's make it harder

    key = 1
    for i in range(NB_ITERATIONS):
        key = key ** e
        key %= N
        key *= start
        key %= N

    return sha256(long_to_bytes(key)).digest()


assert(len(password) == 2)
assert(password.decode().isprintable())

key = derive_key(password)
IV = b"random_and_safe!"
cipher = AES.new(key, AES.MODE_CBC,IV)
enc = cipher.encrypt(pad(flag,16))

with open("flag.enc","wb") as output_file:
    output_file.write(enc)
flag.enc(dump)
    0000  f4 d8 e5 a2 ac 80 6c e9  dc c1 ef 1e d5 c4 51 7c   ......l.......Q|
    0010  e3 d8 84 1a d7 c0 77 c9  9c b0 f6 f0 ab 13 63 b0   ......w.......c.
    0020  f9 5e 8d cd 87 ce c7 d3  88 7a 4a 68 de a9 6f 96   .^.......zJh..o.
    0030  77 cf 1e a7 95 a0 f8 1c  be 3a 66 f0 aa 73 2c 3e   w........:f..s,>
Solution:
Outline:
(1) For preparartion, we calcurate Euler's totient of N by FactorDb( http://www.factordb.com/ ):

N=5*23*61*701*3043975283150884175290138965903193067634156680289693153778518185326633105971710936004483047892546798724665417739250476586249010832824560305913279982496088828053414799963361876618585076997170323631281630177651847

(2) First part of the functuon "derive_key":

for i in range(NB_ITERATIONS):
    start = start ** e
    start %= N
It is easily simplificated by Euler's theorem.

start = pow(bytes_to_long(password),pow(e,NB_ITERATIONS,phi_N), N)
where phi_N is the totient of N,

phi_N=(5-1)* (23-1)* (61-1)* (701-1)* (3043975283150884175290138965903193067634156680289693153778518185326633105971710936004483047892546798724665417739250476586249010832824560305913279982496088828053414799963361876618585076997170323631281630177651847-1)

(3) Second Part of the functuon "derive_key":

    key = 1
    for i in range(NB_ITERATIONS):
        key = key ** e
        key %= N
        key *= start
        key %= N
We can replace it with the following (using "invert" function of gmpy2).

    inv_e = gmpy2.invert(e-1,phi_N)
    key = pow(start, (pow(e,NB_ITERATIONS,phi_N)-1) * inv_e, N)
(4) Finally, We brute force the password and get the flag!

Solver:
solve.py
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from hashlib import sha256
import gmpy2

NB_ITERATIONS = 10871177237854734092489348927
e = 65538
N = 14968794114523720195251887716913440457986979987674770429103169854116498198112478103466085455257317270930523061714030307370028304505577267672733143013124254253285088080041831478700041394909740024011681885623055622400205

#Using FactorDB, we have N=5*23*61*701*3043975283150884175290138965903193067634156680289693153778518185326633105971710936004483047892546798724665417739250476586249010832824560305913279982496088828053414799963361876618585076997170323631281630177651847
phi_N = (5-1)*(23-1)*(61-1)*(701-1)*(3043975283150884175290138965903193067634156680289693153778518185326633105971710936004483047892546798724665417739250476586249010832824560305913279982496088828053414799963361876618585076997170323631281630177651847-1)

def derive_key(password):
    start = bytes_to_long(password)
    start = pow(start,pow(e,NB_ITERATIONS,phi_N), N)
    inv_e = gmpy2.invert(e-1,phi_N)
    key = pow(start, (pow(e,NB_ITERATIONS,phi_N)-1) * inv_e, N)
    return sha256(long_to_bytes(key)).digest()

with open('flag.enc','rb') as f:
    flag_enc = f.read()
    for i in range(0x20, 0x100):
        for j in range(0x20, 0x100):
            password = long_to_bytes(i) + long_to_bytes(j)
            key = derive_key(password)
            IV = b"random_and_safe!"
            cipher = AES.new(key, AES.MODE_CBC,IV)
            flag = cipher.decrypt(flag_enc)
            if(flag[0:6] == b'shkCTF'):
                 print(flag.decode('utf-8')[0:flag.decode('utf-8').find('}')+1])
                 break
Flag:
shkCTF{M4ths_0v3r_p4t13Nce_b4453d1f9f5386a1846e57a3ec95678f}
