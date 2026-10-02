# Encrypted Chat Application

A Python-based encrypted chat application designed for a Cryptography
and Network Security project. The application combines authenticated
user accounts, RSA public-key management, hybrid encryption using
AES-256-GCM and RSA-OAEP, TCP socket communication, and encrypted local
message history.

Security model: This project implements a client-side encrypted,
server-routed chat system. The server authenticates users and routes
encrypted message data, while message encryption and decryption take
place on the clients. Public keys are currently distributed through
the authenticated server, so this implementation should not be
described as a fully verified end-to-end encrypted system.

## Overview

The application allows registered users to communicate through a TCP
client-server architecture.

The main security workflow is:

1. A user authenticates with the server.
2. Each user has an RSA-3072 public/private key pair.
3. The sender obtains the recipient's public key through the
   authenticated server.
4. The sender generates a fresh AES-256 session key for each message.
5. The message is encrypted using AES-256-GCM.
6. The AES session key is encrypted using the recipient's RSA-3072
   public key with RSA-OAEP and SHA-256.
7. The server receives and routes the encrypted message without needing
   the plaintext.
8. The recipient uses their RSA private key to recover the AES session
   key.
9. AES-256-GCM decrypts and authenticates the message.
10. The decrypted message is displayed in the recipient's GUI and stored
    in encrypted local history.

The project was developed as a practical demonstration of cryptography,
authentication, secure network communication, integrity protection, and
secure application design.

## Objectives
- Implement secure client-server communication using TCP sockets.
- Protect chat messages using authenticated encryption.
- Demonstrate hybrid encryption using AES and RSA.
- Secure user passwords using salted PBKDF2-HMAC-SHA256.
- Implement authenticated public-key access and registration.
- Prevent sender spoofing through server-side identity validation.
- Reject invalid and offline message recipients.
- Detect modification of encrypted message data.
- Implement length-prefixed TCP message framing.
- Store local chat history in encrypted form.
- Provide a GUI for practical real-time chat demonstration.

## Features

### Authentication
- User registration and login.
- Password validation.
- Salted PBKDF2-HMAC-SHA256 password hashing.
- Authentication required before protected operations.
- Server-side verification of the authenticated username.

### Cryptography
- AES-256-GCM for message encryption.
- RSA-3072 for public-key cryptography.
- RSA-OAEP with SHA-256 for protecting AES session keys.
- Fresh AES session key for each encrypted message.
- Random 12-byte AES-GCM nonce for each message.
- Authenticated encryption and tamper detection.

### Secure Messaging
- Real-time encrypted chat.
- Server-routed ciphertext.
- Recipient public-key lookup.
- Sender identity verification.
- Recipient existence and online-status validation.
- Immediate display of received messages.

### Local Message History
- Local chat history stored separately from the network protocol.
- Message history encrypted using AES-256-GCM.
- Local history key derived from the user's password using
  PBKDF2-HMAC-SHA256.
- History database stored locally and excluded from Git.

### Network Security
- TCP socket communication.
- 4-byte length-prefixed JSON framing.
- Maximum message-size validation.
- Connection cleanup and online-user tracking.
- Authenticated request handling.

## Testing

The project contains separate tests for:

- AES encryption and tampering.
- RSA encryption and decryption.
- Hybrid encryption.
- Message encryption.
- TCP framing.
- End-to-end tampering.
- Public-key retrieval.
- Authentication and authorization controls.

## System Architecture

```
                    ┌──────────────────────┐
                    │       Client A       │
                    │                      │
                    │  GUI                 │
                    │  Authentication      │
                    │  AES-256-GCM         │
                    │  RSA-3072            │
                    │  Local History       │
                    └──────────┬───────────┘
                               │
                         TCP / JSON
                               │
                               ▼
                    ┌──────────────────────┐
                    │        Server        │
                    │                      │
                    │  Authentication      │
                    │  User Management     │
                    │  Public-Key Lookup   │
                    │  Message Routing     │
                    │  Connection Tracking │
                    └──────────┬───────────┘
                               │
                         TCP / JSON
                               │
                               ▼
                    ┌──────────────────────┐
                    │       Client B       │
                    │                      │
                    │  GUI                 │
                    │  RSA Private Key    │
                    │  AES-256-GCM         │
                    │  Local History       │
                    └──────────────────────┘
```

### Server responsibility

The server handles:
- User registration.
- User authentication.
- Public-key registration and retrieval.
- Authenticated request validation.
- Online-user tracking.
- Encrypted-message routing.
- TCP connection management.

The server does not need the plaintext chat message to route it.

### Client responsibility

The client handles:
- User interaction.
- Key generation and local private-key storage.
- Message encryption.
- Message decryption.
- Local encrypted history.
- GUI rendering.

## Cryptographic Architecture

### 1. Password Security

Passwords are not stored directly.

The application uses:
```
Password
   │
   ▼
Random Salt
   │
   ▼
PBKDF2-HMAC-SHA256
   │
   ▼
Derived Password Hash
```

Current parameters:
- Algorithm: PBKDF2-HMAC-SHA256
- Salt size: 16 bytes
- Derived key size: 32 bytes
- Iterations: 600,000

Password verification uses constant-time comparison through
`hmac.compare_digest()`.

### 2. AES-256-GCM

AES-256-GCM is used for the actual chat message.

For every message:
```
Plaintext
   │
   ▼
Fresh 256-bit AES Key
   │
   ▼
AES-256-GCM
   │
   ├── Random 12-byte Nonce
   └── Ciphertext + Authentication Tag
```

AES-GCM provides both:
- Confidentiality
- Integrity/authentication of the encrypted data

If the ciphertext or authentication data is modified, decryption fails.

### 3. RSA-3072-OAEP

RSA is used to protect the AES session key.

The project uses:
- RSA key size: 3072 bits
- Public exponent: 65537
- Padding: OAEP
- Mask generation function: MGF1
- Hash algorithm: SHA-256

The RSA operation is:
```
AES Session Key
       │
       ▼
Recipient RSA Public Key
       │
       ▼
RSA-OAEP / SHA-256
       │
       ▼
Encrypted AES Session Key
```

The recipient uses the corresponding RSA private key to recover the AES
session key.

## Hybrid Encryption Workflow

The application uses hybrid encryption because symmetric encryption is
efficient for message data while public-key cryptography can protect the
symmetric key.

```
                 SENDER
                   │
             Plaintext Message
                   │
                   ▼
          Generate AES-256 Key
                   │
                   ▼
             AES-256-GCM
                   │
          ┌────────┴────────┐
          │                 │
       Nonce           Ciphertext
          │                 │
          └────────┬────────┘
                   │
                   │
          AES Session Key
                   │
                   ▼
       Recipient RSA Public Key
                   │
                   ▼
            RSA-OAEP/SHA-256
                   │
                   ▼
        Encrypted AES Key
                   │
                   ▼
               SERVER
                   │
          Routes ciphertext
                   │
                   ▼
              RECIPIENT
                   │
       RSA Private Key
                   │
                   ▼
          AES Session Key
                   │
                   ▼
             AES-GCM
                   │
                   ▼
          Original Message
```

The server routes the encrypted fields but does not need to decrypt the
message.

## Network Protocol

TCP does not preserve application-level message boundaries. Therefore,
the application uses explicit length-prefixed JSON framing.

```
┌──────────────┬──────────────────────────┐
│ 4-byte size  │      JSON payload        │
└──────────────┴──────────────────────────┘
```

The 4-byte header stores the payload length using network byte order.

The receiver:
1. Reads exactly 4 bytes.
2. Decodes the message length.
3. Validates the length.
4. Reads exactly that number of bytes.
5. Decodes the JSON payload.

A maximum message size is enforced to prevent unbounded message
allocation.

### Encrypted Message Format

An encrypted message contains the following logical fields:

```json
{
    "type": "encrypted_message",
    "sender": "vindhya",
    "recipient": "siri",
    "encrypted_key": "...",
    "nonce": "...",
    "ciphertext": "..."
}
```

Binary cryptographic values are Base64 encoded before being placed in
JSON.

The server routes these encrypted values after validating:
- Sender is authenticated.
- Sender matches the authenticated account.
- Recipient exists.
- Recipient has a registered public key.
- Recipient is currently online.
- Required encrypted fields are present.

## Project Structure

```
v1/
├── client/
│   ├── __init__.py
│   └── client.py
│
├── database/
│   ├── __init__.py
│   ├── database.py
│   ├── message_history.py
│   ├── chat.db
│   └── chat_history.db
│
├── gui/
│   ├── __init__.py
│   └── app.py
│
├── security/
│   ├── __init__.py
│   ├── aes_utils.py
│   ├── auth.py
│   ├── message_crypto.py
│   ├── network_protocol.py
│   ├── register_public_key.py
│   ├── rsa_utils.py
│   │
│   ├── test_aes.py
│   ├── test_end_to_end.py
│   ├── test_hybrid.py
│   ├── test_message_crypto.py
│   ├── test_network_protocol.py
│   ├── test_public_key.py
│   ├── test_rsa.py
│   └── test_security.py
│
├── server/
│   ├── __init__.py
│   └── server.py
│
├── .gitignore
└── README.md
```

### Generated/local files

The following files are local runtime data and should not be committed:
- `database/chat.db`
- `database/chat_history.db`
- `security/keys/*.pem`

## Technologies Used

| Technology | Purpose |
|------------|---------|
| Python | Application development |
| Tkinter | Desktop GUI |
| TCP sockets | Client-server communication |
| JSON | Application protocol payload |
| SQLite | User and local-history storage |
| cryptography | Cryptographic operations |
| AES-256-GCM | Message encryption |
| RSA-3072 | Public-key encryption |
| RSA-OAEP | AES-key protection |
| PBKDF2-HMAC-SHA256 | Password/key derivation |
| Git | Version control |

### Requirements

Recommended environment used during development:
- Windows
- Python 3.13
- cryptography 50.0.1

The project primarily uses Python standard-library modules plus the
`cryptography` package.

## Installation

1. Open the project directory
   ```bash
   cd C:\Users\vindh\Desktop\projects\EncryptedChat\v1
   ```
2. Install the cryptography dependency
   ```bash
   python -m pip install cryptography
   ```
3. Verify the installation
   ```bash
   python -c "import cryptography; print(cryptography.__version__)"
   ```

## Running the Application

### Start the server

From the project root:
```bash
python -m server.server
```

Expected output:
```
Server started on 127.0.0.1:5000
Waiting for clients...
```

The current development configuration binds the server to:
`127.0.0.1:5000`

### Start the GUI client

Open another PowerShell window:
```bash
cd C:\Users\vindh\Desktop\projects\EncryptedChat\v1
python -m gui.app
```

Start multiple GUI clients if you want to demonstrate communication
between different users.

### User Accounts

Example development accounts used during testing include:
- Username: `vindhya` / Password: `vindhya123`
- Username: `siri` / Password: `siri123`
- Username: `nithya`

These are development/demo credentials. Do not use these credentials in
a production deployment.

### Key Management

RSA key pairs are generated and stored locally under:
`security/keys/`

The key files follow this pattern:
- `<username>_private.pem`
- `<username>_public.pem`

Example:
- `vindhya_private.pem`
- `vindhya_public.pem`
- `siri_private.pem`
- `siri_public.pem`

#### Important security note
Private keys are currently stored as unencrypted PEM files for this
student-project implementation.

In a production system, private keys should be protected using an
operating-system credential store, hardware-backed key storage, or
another appropriate secure key-management mechanism.

## Database

The application uses SQLite for local application data.

### User database
`database/chat.db`

The user database contains information such as:
- User ID
- Username
- Password hash
- Public key
- Account creation time

### Local message history
`database/chat_history.db`

Local history is encrypted before storage.

The local history encryption key is derived from the user's password
using PBKDF2-HMAC-SHA256 rather than storing the password itself.

## Security Controls

The current server implements the following controls.

### Authentication required
Protected operations require successful authentication.
Unauthenticated requests are rejected.

### Sender validation
The `sender` field of an encrypted message must match the authenticated
account.
This prevents an authenticated client from claiming to send a message as
another user.

### Recipient validation
The server verifies that the recipient:
- Exists.
- Has a registered public key.
- Is currently online.

### Public-key authorization
Public-key registration is tied to the authenticated username.
A user cannot register a public key on behalf of another authenticated
account.

### Public-key access control
Public-key retrieval requires authentication.

### Tamper detection
AES-GCM authentication causes modified encrypted data to be rejected
during decryption.
The project tests both:
- Ciphertext modification.
- RSA-encrypted AES-key modification.

### TCP framing validation
The network protocol validates message lengths and reads complete framed
messages before decoding JSON.

## Testing

Tests are organized under:
`security/`

### AES test
```bash
python -m security.test_aes
```
Tests:
- AES-GCM encryption/decryption.
- Ciphertext tampering detection.

### RSA test
```bash
python -m security.test_rsa
```
Tests:
- RSA key generation.
- RSA-OAEP encryption/decryption.
- AES session-key protection.

### Hybrid encryption test
```bash
python -m security.test_hybrid
```
Tests:
- AES + RSA hybrid encryption.
- Ciphertext tampering.
- RSA encrypted-key tampering.

### Message crypto test
```bash
python -m security.test_message_crypto
```
Tests the complete message-level encryption and decryption functions.

### TCP framing test
```bash
python -m security.test_network_protocol
```
Tests the 4-byte length-prefixed JSON protocol.

### End-to-end tampering test
```bash
python -m security.test_end_to_end
```
Tests whether modified encrypted data is rejected.

### Public-key retrieval test
Start the server first:
```bash
python -m server.server
```
Then in another terminal:
```bash
python -m security.test_public_key
```
The test authenticates a user and retrieves another user's public key.

### Security control test
Start the server first:
```bash
python -m server.server
```
Then:
```bash
python -m security.test_security
```
For the offline-recipient test, the specified recipient must not be
logged into the application.

## Verified Test Results

The implemented security tests were executed successfully during
development.

| Test | Result |
|------|--------|
| AES-GCM encryption/decryption | PASS |
| AES-GCM tampering | PASS |
| RSA-OAEP | PASS |
| Hybrid encryption | PASS |
| Hybrid ciphertext tampering | PASS |
| RSA encrypted-key tampering | PASS |
| Message crypto | PASS |
| TCP framing | PASS |
| End-to-end tampering | PASS |
| Wrong password | PASS |
| Invalid recipient | PASS |
| Offline recipient | PASS |
| Sender spoofing | PASS |
| Unauthorized public-key registration | PASS |
| Unauthenticated public-key access | PASS |
| Public-key retrieval | PASS |

```text
Security suite result
========================================
SECURITY TEST SUITE: SUCCESS
All security controls passed.
========================================

Public-key retrieval result
Public key retrieved successfully.
RSA key size: 3072 bits
Public exponent: 65537

PUBLIC KEY RETRIEVAL TEST: SUCCESS
```

## Security Considerations and Limitations

This project is designed as an academic cybersecurity implementation and
demonstration. It should not be treated as a production-ready secure
messaging platform.

1. **Public-key trust**
   Public keys are distributed by the authenticated server.
   There is currently no independent fingerprint verification, certificate
   authority, or out-of-band key verification mechanism.
   Therefore, a compromised or malicious server could potentially provide a
   different public key for a recipient.

2. **Local private-key protection**
   Private RSA keys are currently stored as unencrypted PEM files.
   Production software should provide stronger private-key protection.

3. **Localhost deployment**
   The current server configuration uses:
   `127.0.0.1:5000`
   The current implementation is therefore primarily suitable for local
   demonstration and controlled testing.

4. **Transport security**
   The custom TCP protocol provides framing and application-level
   encryption, but it is not a replacement for a mature transport-security
   protocol such as TLS.

5. **No offline message queue**
   The current server rejects encrypted messages when the recipient is
   offline.
   Persistent server-side message queuing is not part of the current
   implementation.

6. **Key rotation**
   The current implementation does not provide a complete automated
   public-key rotation and revocation system.

## Future Enhancements

Possible future improvements include:
- TLS for transport protection.
- Verified public-key fingerprints.
- Key rotation and revocation.
- Encrypted private-key storage.
- Secure operating-system key stores.
- Multi-factor authentication.
- Rate limiting and account lockout.
- Offline encrypted message queues.
- Message delivery acknowledgements.
- Forward secrecy using an ephemeral key-exchange mechanism.
- Digital signatures for stronger sender authentication.
- Security audit logging.
- Production-grade deployment configuration.
- Secure remote deployment instead of localhost-only operation.

## Viva-Ready Explanation

**What is the main purpose of the project?**
The project demonstrates how cryptographic algorithms can be combined
with network programming to build a secure chat application. Messages
are encrypted on the client before being sent to the server.

**Why is AES used?**
AES is efficient for encrypting the actual message data. AES-256-GCM
additionally provides authentication and tamper detection.

**Why is RSA used?**
RSA is used to protect the AES session key using the recipient's public
key. This allows the sender to securely transfer the symmetric key
material without sending it in plaintext.

**Why use hybrid encryption?**
AES is efficient for bulk data, while RSA provides public-key encryption
for key protection. Combining them provides a practical approach to
secure message exchange.

**Why AES-GCM instead of plain AES?**
AES-GCM provides authenticated encryption. It protects confidentiality
and detects unauthorized modification of the encrypted data.

**What happens if someone changes the ciphertext?**
AES-GCM authentication fails and the recipient rejects the modified
ciphertext during decryption.

**Why use RSA-OAEP?**
OAEP provides randomized padding for RSA encryption and is used with
SHA-256 in this project.

**Why is TCP framing required?**
TCP provides a byte stream rather than application-level message
boundaries. The project therefore adds a 4-byte length prefix before
every JSON message.

**Can the server read the chat plaintext?**
The intended message-routing path does not require the server to receive
plaintext. The sender encrypts the message before routing, and the
recipient decrypts it locally.

**Is this fully end-to-end encrypted?**
Not in the strongest, independently verified sense. The message is
encrypted on the client and routed as ciphertext, but public keys are
currently obtained through the server without independent fingerprint
verification.

**How are passwords stored?**
Passwords are processed using salted PBKDF2-HMAC-SHA256 with 600,000
iterations and are not stored as plaintext.

**What happens when the recipient is offline?**
The current server rejects the encrypted message with:
`Recipient is not online.`

**How is sender spoofing prevented?**
The server compares the sender field in a request with the username
authenticated on that connection. A mismatch is rejected.

### Example Message Flow

Suppose vindhya sends:
`Hello Siri!`
to siri.

**Sender**
```
"Hello Siri!"
      │
      ▼
Generate AES-256 session key
      │
      ▼
AES-256-GCM encryption
      │
      ├── nonce
      └── ciphertext
      │
      ▼
Encrypt AES key using Siri's RSA public key
      │
      ▼
Send encrypted message to server
```

**Server**
```
Authenticate Vindhya
      │
      ▼
Validate sender
      │
      ▼
Validate recipient
      │
      ▼
Check recipient public key
      │
      ▼
Check recipient is online
      │
      ▼
Route encrypted message
```

**Recipient**
```
Receive encrypted message
      │
      ▼
RSA private-key decryption
      │
      ▼
Recover AES session key
      │
      ▼
AES-256-GCM decryption
      │
      ▼
"Hello Siri!"
```

## Academic Relevance

The project demonstrates several core Cryptography and Network Security
concepts:
- Symmetric cryptography.
- Asymmetric cryptography.
- Hybrid encryption.
- Authenticated encryption.
- Password hashing and key derivation.
- Public-key management.
- Authentication and authorization.
- Integrity protection.
- TCP/IP socket communication.
- Secure protocol design.
- Tamper detection.
- Security testing.

The project idea aligns with the Encrypted Chat Application category
using AES, RSA, and sockets described in the project's Cryptography and
Network Security project-ideas material.

## Git and Security

The `.gitignore` excludes local databases and private keys:

```gitignore
# Python cache and compiled files
__pycache__/
*.pyc
*.pyo
*.pyd

# Local databases
database/*.db

# Local RSA keys
security/keys/*.pem
```

Never commit private RSA keys, local databases containing sensitive
information, or real production credentials to a public repository.

## Project Status

- Implementation: Complete for the current academic scope
- Security testing: Passed
- GUI: Functional
- Real-time messaging: Functional
- Cryptographic validation: Passed
- Server authentication controls: Passed
- Tamper detection: Passed
- Public-key retrieval: Passed

## Author

**E. Vindhya Lekhana**
B.Tech Computer Science Engineering
Project: Encrypted Chat Application

## Disclaimer

This project is an academic implementation created for learning and
demonstrating cryptography, network security, authentication, and secure
application development concepts. It has not been independently security
audited and should not be used as a production secure-messaging system
without further security engineering, testing, and review.
