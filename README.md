# Encrypted Chat Application

## 1. Project Overview

The Encrypted Chat Application is a client-server based secure messaging system developed using Python.

The application combines:

- AES-256-GCM for message encryption
- RSA-3072 with OAEP for protecting AES session keys
- TCP sockets for network communication
- SQLite for user account storage
- PBKDF2-HMAC-SHA256 for password hashing
- Tkinter for the graphical user interface
- Length-prefixed JSON messages for reliable TCP framing

The main objective is to demonstrate how symmetric encryption, asymmetric encryption, authentication, and network communication can be combined to build a secure chat application.

---

## 2. Objectives

The major objectives of the project are:

1. Develop a client-server chat application using TCP sockets.
2. Implement secure user authentication.
3. Store passwords using a salted password-hashing mechanism.
4. Generate RSA key pairs for users.
5. Store user public keys on the server.
6. Encrypt chat messages using AES-256-GCM.
7. Protect AES session keys using RSA-OAEP.
8. Detect modification of encrypted messages.
9. Prevent sender identity spoofing at the server.
10. Provide a user-friendly graphical interface.
11. Demonstrate practical cryptographic security concepts.

---

## 3. Technologies Used

| Component             | Technology           |
| --------------------- | -------------------- |
| Programming Language  | Python               |
| GUI                   | Tkinter              |
| Network Communication | TCP Sockets          |
| Symmetric Encryption  | AES-256-GCM          |
| Asymmetric Encryption | RSA-3072             |
| RSA Padding           | OAEP with SHA-256    |
| Password Hashing      | PBKDF2-HMAC-SHA256   |
| Database              | SQLite               |
| Data Format           | JSON                 |
| TCP Framing           | 4-byte length prefix |
| Cryptographic Library | Python cryptography  |

---

## 4. System Architecture

The application follows a client-server architecture.

```text
                    ┌──────────────────────┐
                    │      SQLite DB       │
                    │                      │
                    │ Users                │
                    │ Password hashes      │
                    │ Public keys          │
                    └──────────▲───────────┘
                               │
                               │
┌──────────────────┐           │           ┌──────────────────┐
│   Vindhya Client │           │           │    Siri Client  │
│                  │           │           │                  │
│ Tkinter GUI      │           │           │ Tkinter GUI      │
│ RSA Private Key  │           │           │ RSA Private Key  │
│ AES-GCM          │           │           │ AES-GCM          │
└────────┬─────────┘           │           └────────┬─────────┘
         │                     │                    │
         │                     │                    │
         │              TCP Connection             │
         │                     │                    │
         └─────────────────────┼────────────────────┘
                               │
                     ┌─────────▼─────────┐
                     │      Server       │
                     │                   │
                     │ Authentication    │
                     │ Public-key lookup │
                     │ Message routing   │
                     │ Session tracking  │
                     └───────────────────┘
```

The server routes encrypted message packets but does not need the plaintext message to perform message delivery.

---

## 5. Hybrid Encryption Design

The application uses hybrid encryption because AES and RSA have different strengths.

### AES-256-GCM

AES is used for the actual chat message because symmetric encryption is efficient for larger amounts of data.

For each message:

1. A random 256-bit AES session key is generated.
2. A random 96-bit nonce is generated.
3. AES-GCM encrypts the plaintext.
4. AES-GCM also produces an authentication tag.
5. The resulting ciphertext is sent as part of the encrypted packet.

### RSA-3072

RSA is used to protect the AES session key.

The recipient's RSA public key is obtained from the server.

The AES session key is encrypted using:

* RSA-3072
* OAEP padding
* SHA-256

Only the recipient's RSA private key can recover the protected AES session key.

---

## 6. Message Encryption Flow

When Vindhya sends a message to Siri:

```text
Plaintext
    │
    ▼
Generate random AES-256 session key
    │
    ▼
AES-256-GCM encryption
    │
    ├── Nonce
    └── Ciphertext + authentication tag
    │
    ▼
Encrypt AES session key
using Siri's RSA public key
    │
    ▼
RSA-OAEP encrypted AES key
    │
    ▼
Encrypted JSON packet
    │
    ▼
TCP connection
    │
    ▼
Server
    │
    ▼
Siri
```

The server forwards the encrypted packet to the recipient.

---

## 7. Message Decryption Flow

When Siri receives the message:

```text
Encrypted JSON packet
        │
        ▼
Extract encrypted AES key
        │
        ▼
RSA-OAEP decryption
using Siri's private key
        │
        ▼
Recover AES session key
        │
        ▼
AES-256-GCM decryption
        │
        ▼
Authentication verification
        │
        ▼
Original plaintext message
```

If the encrypted data has been modified, AES-GCM authentication or RSA-OAEP decryption fails.

---

## 8. Authentication

User passwords are not stored directly.

The application uses:

```text
PBKDF2-HMAC-SHA256
```

with:

* Random 16-byte salt
* 600,000 iterations
* 32-byte derived hash

The database stores the encoded salt and password hash.

During login:

```text
Entered password
       │
       ▼
Retrieve stored salt
       │
       ▼
PBKDF2-HMAC-SHA256
       │
       ▼
Derived password hash
       │
       ▼
Constant-time comparison
       │
       ▼
Login accepted/rejected
```

---

## 9. RSA Key Management

Each user has an RSA key pair.

```text
RSA Key Pair
│
├── Public Key
│     └── Registered with server
│
└── Private Key
      └── Stored locally on the client
```

The current implementation generates:

* RSA key size: 3072 bits
* Public exponent: 65537
* Private key format: PKCS8 PEM
* Public key format: SubjectPublicKeyInfo PEM

Private keys are not sent to the server.

---

## 10. TCP Communication

TCP is a stream protocol and does not preserve application-level message boundaries.

Therefore, the application uses a 4-byte length prefix before every JSON message.

```text
┌────────────────┬──────────────────────────┐
│ 4-byte length  │ JSON message             │
└────────────────┴──────────────────────────┘
```

The receiver first reads the 4-byte header and determines how many bytes belong to the JSON message.

This prevents problems caused by TCP packet fragmentation or multiple application messages arriving together.

---

## 11. Security Controls

The server implements several security controls.

### Authentication

A client must successfully authenticate before accessing authenticated operations.

### Sender Verification

The server associates a TCP connection with the authenticated username.

For every encrypted message:

```text
authenticated username == sender
```

must be true.

This prevents simple sender spoofing.

### Public-Key Protection

A user can only register a public key for their own authenticated account.

### Recipient Validation

The server verifies that:

* The recipient exists.
* The recipient has a registered public key.
* The recipient is currently online.

### Message Integrity

AES-GCM detects modification of ciphertext.

RSA-OAEP protects the AES session key against unauthorized recovery and detects invalid RSA ciphertext during decryption.

---

## 12. Security Testing

The project includes individual cryptographic tests and application-level security tests.

### AES-GCM Test

Result:

```text
AES-GCM DECRYPTION TEST: SUCCESS
TAMPER TEST: SUCCESS
Modified ciphertext was rejected.
```

### RSA-OAEP Test

Result:

```text
RSA-OAEP TEST: SUCCESS
The AES session key was recovered correctly.
```

### Hybrid Encryption Test

Result:

```text
HYBRID ENCRYPTION TEST: SUCCESS
TAMPER TEST: SUCCESS
RSA TAMPER TEST: SUCCESS
```

### TCP Framing Test

Result:

```text
TCP FRAMING TEST: SUCCESS
```

### Public Key Retrieval Test

Result:

```text
PUBLIC KEY RETRIEVAL TEST: SUCCESS
RSA key size: 3072 bits
Public exponent: 65537
```

### Message Crypto Test

Result:

```text
MESSAGE CRYPTO TEST: SUCCESS
```

### Application Security Test

The following tests passed:

```text
WRONG PASSWORD TEST: PASS

INVALID RECIPIENT TEST: PASS

OFFLINE RECIPIENT TEST: PASS

SENDER SPOOFING TEST: PASS

UNAUTHORIZED PUBLIC KEY TEST: PASS

UNAUTHENTICATED KEY TEST: PASS
```

### End-to-End Tampering Test

Result:

```text
AES-GCM TAMPER TEST: PASS

HYBRID CIPHERTEXT TAMPER TEST: PASS

RSA ENCRYPTED-KEY TAMPER TEST: PASS

END-TO-END TAMPERING TEST: SUCCESS
```

---

## 13. GUI Features

The application provides a graphical chat interface with:

* User login
* Account registration
* Recipient selection
* Secure connection status
* Message sending
* Message receiving
* Message timestamps
* Encryption technology indicator
* Logout
* Automatic RSA key generation for new users

The GUI displays:

```text
AES-256-GCM + RSA-OAEP
```

to indicate the cryptographic mechanisms used for message protection.

---

## 14. Database

SQLite is used to store user account information.

The main table is:

```text
users
```

with fields:

```text
user_id
username
password_hash
public_key
created_at
```

The database does not store plaintext passwords.

---

## 15. Project Security Model

The application provides client-side encryption of chat messages.

The server receives and routes encrypted message packets.

The server does not perform AES decryption of chat messages.

However, the current project should not be described as a fully verified end-to-end encryption system.

The server currently distributes public keys. Without an independent public-key authentication mechanism such as certificate validation, verified fingerprints, or a trusted key directory, a malicious or compromised server could potentially replace a recipient's public key.

Therefore, the most accurate description is:

> "A client-side encrypted chat application using hybrid AES-GCM and RSA-OAEP encryption with server-based message routing."

---

## 16. Current Security Limitations

### 1. Public-key trust

Public keys are obtained from the server.

A stronger production design would authenticate public keys using:

* Key fingerprints
* Certificates
* A trusted key directory
* User verification

### 2. Private-key storage

Private RSA keys are currently stored locally as PEM files without encryption.

A production implementation should protect private keys using:

* OS key stores
* Hardware-backed key storage
* Password-protected private-key files

### 3. Transport security

The demonstration server uses TCP directly.

For deployment over an untrusted network, TLS should be added to protect:

* Login credentials
* Public-key requests
* Metadata
* Network traffic

The cryptographic message layer and TLS would provide different security properties.

### 4. Message persistence

The current application focuses on real-time messaging and does not provide persistent encrypted chat history.

---

## 17. Future Enhancements

Possible future improvements include:

1. TLS-secured client-server communication.
2. Verified public-key fingerprints.
3. Encrypted private-key storage.
4. Secure encrypted message history.
5. Group chat.
6. File encryption and secure file transfer.
7. Multi-factor authentication.
8. Online/offline presence management.
9. Message delivery status.
10. Stronger identity verification.
11. Key rotation.
12. Forward secrecy using modern ephemeral key-exchange mechanisms.

---

## 18. How to Run the Application

### Start the server

Open Command Prompt:

```cmd
cd C:\Users\vindh\Desktop\projects\EncryptedChat
python -m server.server
```

Expected output:

```text
Server started on 127.0.0.1:5000
Waiting for clients...
```

### Start the GUI

Open another Command Prompt:

```cmd
cd C:\Users\vindh\Desktop\projects\EncryptedChat
python -m gui.app
```

### Register

Select:

```text
Create New Account
```

Enter a username and password.

### Login

Use the registered credentials.

The application automatically generates an RSA key pair for users who do not already have one and registers the public key with the authenticated server session.

### Start a chat

Enter the recipient username and click:

```text
Connect
```

Then enter a message and click:

```text
Send
```

---

## 19. Security Test Commands

### AES test

```cmd
python -m security.test_aes
```

### RSA test

```cmd
python -m security.test_rsa
```

### Hybrid encryption test

```cmd
python -m security.test_hybrid
```

### Message crypto test

```cmd
python -m security.test_message_crypto
```

### TCP framing test

```cmd
python -m security.test_tcp_framing
```

### Public-key retrieval test

```cmd
python -m security.test_public_key
```

### Application security tests

```cmd
python -m security.test_security
```

### End-to-end tampering tests

```cmd
python -m security.test_end_to_end
```

---

## 20. Conclusion

The Encrypted Chat Application demonstrates the practical use of cryptography and network security concepts in a real-time messaging system.

The project combines:

```text
Authentication
     +
PBKDF2 Password Hashing
     +
RSA-3072
     +
RSA-OAEP
     +
AES-256-GCM
     +
TCP Sockets
     +
TCP Message Framing
     +
SQLite
     +
Tkinter GUI
```

The implementation successfully provides encrypted message transmission, authentication, integrity protection, RSA-based session-key protection, sender validation, and security testing.

The project also identifies important security limitations and possible improvements required for production-grade secure messaging.
