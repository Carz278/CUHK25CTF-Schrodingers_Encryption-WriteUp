# CTF Write-Up: Schrödinger's Encryption

**Type:** Cryptography  
**Title:** Schrödinger's Encryption  
**Author:** chemistrying ★★☆☆  
**Description:** *"It's the duality of encryption - the safety and security."*  
**Connection:** `nc chall.25.cuhkctf.org 25060`

---

## 1. Challenge Overview

We are given a ZIP file containing the source code for a custom encryption system. The service running on the challenge server encrypts the flag using a non-deterministic cipher and allows us to request multiple encryptions. Our goal is to decrypt the flag from these ciphertexts.

The core idea is that the encryption is probabilistic—it randomly chooses between two different bitwise operations. By collecting many samples and performing statistical analysis, we can recover the original flag.

---

## 2. Source Code Analysis

Let's break down the provided Python files.

### 2.1 `magicrypt.py`

This file defines the core encryption routines.

- `andcryption(message, key)`: Performs a bitwise AND (`m & k`) between the message and a random key of the same length.
- `orcryption(message, key)`: Performs a bitwise OR (`m | k`) between the message and a random key of the same length.
- `schrodingers_cat(message)`: The main encryption function. It:
  - Generates a random key of the same length as the message.
  - Randomly chooses either `andcryption` or `orcryption` to encrypt the message.
  - Returns the ciphertext as a hex string (`0x...`).

**Key Insight:** The encryption method is chosen randomly for each encryption, and a new random key is generated each time.

### 2.2 `main.py`

This script simulates a conversation between Alice and Bob.

- Bob reads the flag from `flag.txt`.
- Bob "encrypts" the flag using `schrodingers_cat` and sends the ciphertext to Alice.
- The user (Alice) is prompted to guess the flag.
- If the guess is wrong, Bob sends another encryption of the flag, and the loop continues.

This allows us to collect multiple ciphertexts of the same flag encrypted with different random keys and random operation choices (AND or OR).

### 2.3 `person.py`

A simple helper class to simulate the conversation with timed delays.

---

## 3. Vulnerability: Statistical Analysis of Bitwise Operations

The cryptographic weakness stems from the probabilistic nature of the encryption scheme. By analyzing the statistical distribution of ciphertext bits, we can deduce the original flag bits.

### 3.1 Bitwise Operation Analysis

For each bit position `i` in the flag (`f_i`), key (`k_i`), and ciphertext (`c_i`):

#### AND Operation (`c_i = f_i AND k_i`)
- **If `f_i = 0`**: `c_i = 0` (always)
- **If `f_i = 1`**: `c_i = k_i` (50% probability of being 1)

#### OR Operation (`c_i = f_i OR k_i`)
- **If `f_i = 0`**: `c_i = k_i` (50% probability of being 1)
- **If `f_i = 1`**: `c_i = 1` (always)

### 3.2 Probability Distribution

| Flag Bit (`f_i`) | Pr(c_i = 1 \| AND) | Pr(c_i = 1 \| OR) | Overall Pr(c_i = 1) |
|------------------|--------------------|-------------------|---------------------|
| 0                | 0%                 | 50%               | 25%                 |
| 1                | 50%                | 100%              | 75%                 |

Since the encryption randomly selects between AND and OR operations with equal probability, the overall probability distribution reveals:

- **Flag bit = 0**: 25% probability of ciphertext bit being 1
- **Flag bit = 1**: 75% probability of ciphertext bit being 1

This statistical bias enables us to recover the original flag bits by analyzing the frequency of 1s across multiple ciphertext samples.

---

## 4. Exploitation Strategy

The attack methodology involves:

1. **Establish Connection**: Connect to the challenge server
2. **Data Collection**: Gather multiple ciphertext samples by submitting incorrect flag guesses
3. **Bit Frequency Analysis**: For each bit position:
   - Count occurrences of 1 across all samples
   - Calculate frequency percentage
   - Classify flag bit based on statistical threshold (50%)
4. **Flag Reconstruction**: Assemble recovered bits into the complete flag
5. **Flag Submission**: Submit the reconstructed flag to the server

---

## 5. Solution Implementation

The `solve.py` script executes the following attack workflow:

- **Network Communication**: Establishes TCP connection to the challenge server
- **Sample Collection**: Accumulates ciphertext samples through iterative incorrect submissions
- **Statistical Processing**: 
  - Converts hex ciphertexts to binary representation
  - Computes bit-wise frequency distributions
  - Applies threshold classification for bit recovery
- **Result Validation**: Submits the reconstructed flag for verification

### Solve.py
- **python**
```
import socket
import binascii
import time
import re

def solve():
    s = socket.socket()
    s.connect(('chall.25.cuhkctf.org', 25060))
    
    samples = []
    
    # 接收初始数据
    data = b""
    while True:
        chunk = s.recv(1024)
        data += chunk
        if b'0x' in data and b'Now tell me the flag' in data:
            break
    
    # 提取第一个加密数据
    text = data.decode('latin-1', errors='ignore')
    hex_match = re.search(r'0x([0-9a-f]+)', text)
    if hex_match:
        hex_str = hex_match.group(1)
        try:
            encrypted = binascii.unhexlify(hex_str)
            samples.append(encrypted)
            print(f"Sample 1: {len(encrypted)} bytes")
        except:
            pass
    
    # 收集更多样本
    for i in range(300):  # 大量样本
        try:
            s.send(b"dummy\n")
            time.sleep(0.1)
            data = s.recv(4096)
            text = data.decode('latin-1', errors='ignore')
            hex_matches = re.findall(r'0x([0-9a-f]+)', text)
            for hex_str in hex_matches:
                try:
                    if len(hex_str) % 2 == 0:
                        encrypted = binascii.unhexlify(hex_str)
                        samples.append(encrypted)
                        if len(samples) % 50 == 0:
                            print(f"Sample {len(samples)} collected")
                except:
                    continue
        except:
            continue
        
        if len(samples) >= 300:
            break
    
    print(f"Collected {len(samples)} samples")
    
    if not samples:
        print("No samples collected")
        return
    
    flag_len = min(len(s) for s in samples)
    print(f"Flag length: {flag_len}")
    
    samples = [s[:flag_len] for s in samples]
    
    # 统计方法
    flag_bytes = bytearray(flag_len)
    for byte_idx in range(flag_len):
        for bit_idx in range(8):
            bit_pos = 7 - bit_idx
            
            # 计算该位为1的频率
            count_ones = 0
            for sample in samples:
                bit = (sample[byte_idx] >> bit_pos) & 1
                if bit == 1:
                    count_ones += 1
            
            freq = count_ones / len(samples)
            
            # 根据频率判断
            if freq > 0.5:  # 更可能f=1
                flag_bytes[byte_idx] |= (1 << bit_pos)
            # 否则保持0（更可能f=0）
    
    flag = flag_bytes.decode('ascii', errors='ignore')
    print("Recovered flag:", repr(flag))
    
    # 提交答案
    s.send(flag_bytes + b"\n")
    time.sleep(1)
    try:
        response = s.recv(4096)
        print(response.decode())
    except:
        print("No response")

if __name__ == '__main__':
    solve()

```

### Execution Output
**Output:**
```
Sample 1: 96 bytes
Sample 50 collected
Collected 73 samples
Flag length: 96
Recovered flag: cuhk25ctf{br34kin_schr0d1ng3r5_cORt_wIth_mu1t1p1e_ANDcryptions_aeb5914d8af2cb1655ecbc07c1cd71f6}
```

---

## 6. Conclusion

This challenge demonstrates a classic bit-flipping frequency analysis attack. The vulnerability arises from using reversible but probabilistic operations without sufficient masking. The "Schrödinger" theme is apt—until observed (via many samples), the flag exists in a superposition of states, but measurement (statistical analysis) collapses it to the correct value.

**Flag:**  
`cuhk25ctf{br34kin_schr0d1ng3r5_cORt_wIth_mu1t1p1e_ANDcryptions_aeb5914d8af2cb1655ecbc07c1cd71f6}`
