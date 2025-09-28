
CTF Write-Up: Schrödinger's Encryption
Type: Cryptography
Title: Schrödinger's Encryption
Author: chemistrying ★★☆☆
Description: "It's the duality of encryption - the safety and security."
nc chall.25.cuhkctf.org 25060
1. Challenge Overview
We are given a ZIP file containing the source code for a custom encryption system. The service running on the challenge server encrypts the flag using a non-deterministic cipher and allows us to request multiple encryptions. Our goal is to decrypt the flag from these ciphertexts.
The core idea is that the encryption is probabilistic—it randomly chooses between two different bitwise operations. By collecting many samples and performing statistical analysis, we can recover the original flag.
2. Source Code Analysis
Let's break down the provided Python files.
2.1 magicrypt.py
This file defines the core encryption routines.
andcryption(message, key): Performs a bitwise AND (m & k) between the message and a random key of the same length.
orcryption(message, key): Performs a bitwise OR (m | k) between the message and a random key of the same length.
schrodingers_cat(message): The main encryption function. It:
Generates a random key of the same length as the message.
Randomly chooses either andcryption or orcryption to encrypt the message.
Returns the ciphertext as a hex string (0x...).
Key Insight: The encryption method is chosen randomly for each encryption, and a new random key is generated each time.
2.2 main.py
This script simulates a conversation between Alice and Bob.
Bob reads the flag from flag.txt.
Bob "encrypts" the flag using schrodingers_cat and sends the ciphertext to Alice.
The user (Alice) is prompted to guess the flag.
If the guess is wrong, Bob sends another encryption of the flag, and the loop continues.
This allows us to collect multiple ciphertexts of the same flag encrypted with different random keys and random operation choices (AND or OR).
2.3 person.py
A simple helper class to simulate the conversation with timed delays.
3. Vulnerability: Probabilistic Bit Recovery
The security of this system relies on the attacker not knowing whether AND or OR was used for each bit. However, we can exploit the statistical properties of these operations.
Let's consider a single bit position i in the flag (f_i), the key (k_i), and the resulting ciphertext bit (c_i).
If the operation is AND:
c_i = f_i AND k_i
If f_i = 0, then c_i is always 0.
If f_i = 1, then c_i = k_i (so it's 1 with 50% probability and 0 with 50% probability).
If the operation is OR:
c_i = f_i OR k_i
If f_i = 0, then c_i = k_i (so it's 1 with 50% probability and 0 with 50% probability).
If f_i = 1, then c_i is always 1.
Now, let's analyze the probability that c_i = 1 given f_i:
Flag Bit f_i
Pr(c_i = 1 | AND)
Pr(c_i = 1 | OR)
Overall Pr(c_i = 1)
0
0%
50%
25%
1
50%
100%
75%

Since the encryption randomly chooses between AND and OR with equal probability, the overall probability that a ciphertext bit is 1 is:
25% if the flag bit is 0
75% if the flag bit is 1
Therefore, by collecting enough ciphertexts and counting the frequency of 1s at each bit position, we can determine the original flag bits:
If the frequency is close to 25%, the flag bit is 0.
If the frequency is close to 75%, the flag bit is 1.
4. The Exploit
The solution involves:
Connecting to the server and triggering the encryption loop.
Collecting a large number of ciphertexts (hex strings) by sending incorrect guesses.
Converting each hex string to a bytes object.
For each bit position in the flag:
Count how many ciphertexts have a 1 at that position.
Calculate the frequency of 1s.
If the frequency is above 50%, set the flag bit to 1; otherwise, set it to 0.
Assemble the recovered bits into the flag string and submit it.
5. Solution Script
The provided solve.py implements this attack:
Socket Connection: Connects to the challenge server.
Data Collection: Reads the initial ciphertext and then collects hundreds more by sending dummy answers.
Statistical Analysis:
For each byte position and each bit within that byte, it calculates the frequency of 1s across all samples.
Bits with high frequency (>50%) are set to 1 in the flag.
Flag Submission: Sends the recovered flag to the server.
Output:

The server then confirms the correct flag.
6. Conclusion
This challenge demonstrates a classic bit-flipping frequency analysis attack. The vulnerability arises from using reversible but probabilistic operations without sufficient masking. The "Schrödinger" theme is apt—until observed (via many samples), the flag exists in a superposition of states, but measurement (statistical analysis) collapses it to the correct value.
Flag: cuhk25ctf{br34kin_schr0d1ng3r5_cORt_wIth_mu1t1p1e_ANDcryptions_aeb5914d8af2cb1655ecbc07c1cd71f6}

