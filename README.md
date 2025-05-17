# Cryptographic Library

This cryptographic library includes:
- MD5 hash function
- SHA1 hash function
- RSA encryption algorithm
- Key generator
- HMAC data authentication

## Compilation

To compile the project, run the following commands in terminal:

```bash
mkdir build && cd build
cmake ..
make
./Cryptolib help
```

# HMAC (Keyed-Hashing for Message Authentication)

Mechanism for message authentication using cryptographic hash functions. HMAC can be used with any 
iterative cryptographic hash function, e.g., MD5, SHA-1, in combination with a secret shared key.  
The cryptographic strength of HMAC depends on the properties of the underlying hash function.

RFC HMAC:
https://datatracker.ietf.org/doc/html/rfc2104


# MD5 Algorithm

From the input string, we always create a string whose length is a multiple of 64 bytes.  
For example, our input string: "hello" is 5 bytes long. We must transform it into a string whose length is a multiple of 64 bytes.  
First, append a single byte (0x80), then append zero bytes (00) until the length of the sequence becomes congruent to 56 modulo 64.  
Finally, store the original 64-bit length of the array in the last 8 bytes:

```
68656c6c6f 80 0000..00 0000000000000040
```

Initialize constant values necessary for hashing:

1. Array **T** of 64 32-bit values:

![image](https://github.com/user-attachments/assets/ca5bbfc2-2c2b-4cad-a2c5-6325ecc1ac0a)


2. Variables: `a = 0x67452301`, `b = 0xefcdab89`, `c = 0x98badcfe`, `d = 0x10325476`; which will change and store the final hash value

3. Functions **F(), G(), H(), I()**, which take 3 out of 4 variables as inputs and perform bitwise operations:

F(uint32_t x, uint32_t y, uint32_t z) return (x & y) | (~x & z);

G(uint32_t x, uint32_t y, uint32_t z) return (x & z) | (~z & y);

H(uint32_t x, uint32_t y, uint32_t z) return x ^ y ^ z;

I(uint32_t x, uint32_t y, uint32_t z) return y ^ (~z | x);


Divide the data into 64-byte chunks and begin processing (as our data is only 64 bytes, there will be just 1 iteration).  
On each iteration, save the values of `a`, `b`, `c`, and `d` to add them to the modified values at the end of the iteration:

```
A = a, B = b, C = c, D = d
```

There will be 64 rounds in total. First 16 rounds use the function **F()**, the second 16 rounds use the function **G()**, third 16 rounds use **H()**, and the last 16 rounds use **I()**.  
A left shift operation by a predetermined standardized value is applied to the result.

Each round has the following format:

![image](https://github.com/user-attachments/assets/2f6a0952-eedf-41a4-b547-365f44df1962)



```
a += A, b += B, c += C, d += D
```


RFC MD5:
https://www.ietf.org/rfc/rfc1321.txt

How MD5 works (in russian):
https://www.youtube.com/watch?v=xV8USnjKGCU&pp=0gcJCfcAhR29_xXO (from 14:15)

Animation of rounds in MD5 (in english):
https://www.youtube.com/watch?v=5MiMK45gkTY (from 5:53)


# SHA-1 Algorithm

SHA-1, like MD5, processes the message in 512-bit (64-byte) chunks but produces a 160-bit (20-byte) digest.
Append 0x80, followed by as many 0x00 as needed so that length is congruent to 448 mod 512.
Append the original message length as a 64-bit big-endian integer.

1. Initialize constants: `h0 = 0x67452301`, `h1 = 0xEFCDAB89`, `h2 = 0x98BADCFE`, `h3 = 0x10325476`, `h4 = 0xC3D2E1F0`.
2. Process each 512-bit chunk:
   Create an array w[80]. The first 16 words come directly from the chunk (big-endian). Remaining words are generated.
3. Main loop in 80 rounds:
   
   ![image](https://github.com/user-attachments/assets/6910fd92-85fe-49ca-9ed4-c8c2a5189a31)
5. Add chunk's hash to the result: `h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;`


RFC SHA-1: 
https://datatracker.ietf.org/doc/html/rfc3174

SHA-1 Steps: 
https://www.slideshare.net/slideshow/sha-1-algorithmppt/256179654


# RSA

RSA is an asymmetric (public-key) cryptosystem used for encryption and digital signatures.

1. Key generation:
   
   Choose two distinct prime numbers `p` and `q`.
   
   Compute `n = p * q`.
   
   Compute Euler's totient `φ(n) = (p - 1) * (q - 1)`.
   
   Choose public exponent `e` such that `1 < e < φ(n)` and `gcd(e, φ(n)) = 1`.

   Compute private exponent `d = e⁻¹ mod φ(n)`.

   Public key: `(n, e)` and Private key: `(n, d)`.

2. Encryption:

   `c = mᵉ mod n`

3. Decryption:

   `m = cᵈ mod n`

RSA Visual:
https://legacy.cryptool.org/en/cto/rsa-visual

RFC RSA:
https://datatracker.ietf.org/doc/html/rfc8017


# MD5 Алгоритм

Из входной строки всегда делаем строку которая кратна 64 байтам.
Например, наша входная строка: "hello" - 5 байтов. Мы должны привести её к строке кратной 64 байтам.
Сначала добавляем единичный байт (0х80), затем добавляем нулевые байты (00), пока длина последовательности не станет сравнима с 56 по модулю 64,
в последние 8 байтов запишем 64-битный размер исходного массива:

68656c6c6f 80 0000..00 0000000000000040

Проинициализируем константные значения необходимые для хеширования:

1. Массив T из 64 32-битных значений
2. Переменные: a = 0x67452301; b = 0xefcdab89; c = 0x98badcfe; d = 0x10325476; которые будут изменяться и хранить итоговый хеш
3. Функции F(), G(), H(), I(), которые будут принимать на вход 3 из 4 переменных и проводят битовые операции

Разбиваем данные по 64 байта и начинаем обработку (т.к. у нас данные всего на 64 байта, будет только 1 итерация):
На каждой итерации сохраняем значение a, b, c, d, чтобы в конце итерации сложить их с измененными значениями

A = a, B = b, C = c, D = d

Всего будет выполнено 64 раунда. Первые 16 раундов функция F(), вторые 16 раундов функция G(), третие 16 раундов - H(), четвертые 16 раундов - I()
К тому, что получилось применяется сдвиг влево на заранее установленное стандартизованное значение.

a += A, b += B, c += C, d += D
