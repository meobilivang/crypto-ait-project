# Planning

## 0. Optional tasks

- Restructure project.
  - files under `/siftprotocols` are being duplicated under `/servers` & `/clients`
  - Maybe symlink this later on? Be aware that moving this directory around my mess up with the path to `/users` and `key.txt`

## 1. RSA key genereation

Generate key on server side.

- Server: holds both public + private key
- Client: holds the public key

Passphrase handling?

## 2. MTP message

### Header

> Adding new fields to header. modify siftmpt.py

#### v0.5 MTP

SiFT v0.5 MTP messages have a 6-byte header that consists of the following fields:

- __ver__: A 2-byte _version number_ field, where the first byte is the major version (i.e., 0 in case of v0.5) and the second byte is the minor version (i.e., 5 in case of v0.5). This means that messages conforming this specification must start with the byte sequence `00 05`.
- __typ__: A 2-byte _message type_ field that specifies the type of the payload in the message. The following message types are supported by SiFT v0.5:
  - `00 00` : _login_req_ (login request)
  - `00 10` : _login_res_ (login response)
  - `01 00` : _command_req_ (command request)
  - `01 10` : _command_res_ (command response)
  - `02 00` : _upload_req_0_ (upload request containing a file fragment)
  - `02 01` : _upload_req_1_ (upload request containing the last file fragment)
  - `02 10` : _upload_res_ (upload response)
  - `03 00` : _dnload_req_ (download request)
  - `03 10` : _dnload_res_0_ (download response containing a file fragment)
  - `03 11` : _dnload_res_1_ (download response containing the last file fragment)
- __len__: A 2-byte _message length_ field that contains the length of the entire message (including the header) in bytes (using big endian byte order).

#### v1.0 MTP

SiFT v1.0 MTP messages have a 16-byte header that consists of the following fields:

- __ver__: A 2-byte _version number_ field, where the first byte is the major version (i.e., 1 in case of v1.0) and the second byte is the minor version (i.e., 0 in case of v1.0). This means that messages conforming this specification must start with the byte sequence `01 00`.
- __typ__: A 2-byte _message type_ field that specifies the type of the payload in the message. The following message types are supported by SiFT v1.0:
  - `00 00` : _login_req_ (login request)
  - `00 10` : _login_res_ (login response)
  - `01 00` : _command_req_ (command request)
  - `01 10` : _command_res_ (command response)
  - `02 00` : _upload_req_0_ (upload request containing a file fragment)
  - `02 01` : _upload_req_1_ (upload request containing the last file fragment)
  - `02 10` : _upload_res_ (upload response)
  - `03 00` : _dnload_req_ (download request)
  - `03 10` : _dnload_res_0_ (download response containing a file fragment)
  - `03 11` : _dnload_res_1_ (download response containing the last file fragment)
- __len__: A 2-byte _message length_ field that contains the length of the entire message (including the header) in bytes (using big endian byte order).
- __sqn__: A 2-byte _message sequence number_ field that contains the sequence number of this message (using big endian byte order).
- __rnd__: A 6-byte _random_ field that contains freshly generated random bytes.
- __rsv__: A 2-byte _reserved_ field which is not used in this version of the protocol (reserved for future versions). The value of this field in messages conforming this specification should be `00 00`.

### Payload

#### Login request

In case of login requests (i.e., message type `00 00`), the message format is somewhat different, and it is shown below:

- 16-byte Header

```
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 |  ver  |  typ  |  len  |  sqn  |          rnd          |  rsv  |
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 |                                                               |
 +                                                               +
 |                                                               |
 .                                                               .
 .                    encrypted payload (epd)                    .
 .                                                               .
 |                                                               |
 +                                                               +
 |                                                               |
 +               +---+---+---+---+---+---+---+---+---+---+---+---+
 |               |                      mac                      |
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 |                                                               |
 .                                                               .
 .                encrypted temporary key (etk)                  .
 .                                                               .
 |                                                               |
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

The difference is that, in case of a login request, the MTP message contains an encrypted temporary key (__etk__) following the mac field. The temporary key is a 32-byte AES key, which is used to produce the encrypted payload (epd) and the authentication tag (mac) of the message using AES in GCM mode. This temporary key is encrypted using RSA-OAEP with a 2048-bit RSA public key. Thus, the encrypted temporary key (etk) field is 256 bytes  (2048 bits) long. The login request message is sent by the client to the server, and it is produced using a freshly generated temporary key and the RSA public key of the server as described below.

**What to add?**

- 32-byte AES key = temp key (etk) -> produce encrypted payload (epd) + auth tag (mac)
=> Encrypted etk = 256 bytes

#### Other

All SiFT v1.0 MTP messages (except when the payload is a login request) has the following format:

- 16-byte header

```
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 |  ver  |  typ  |  len  |  sqn  |          rnd          |  rsv  |
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
 |                                                               |
 +                                                               +
 |                                                               |
 .                                                               .
 .                    encrypted payload (epd)                    .
 .                                                               .
 |                                                               |
 +                                                               +
 |                                                               |
 +               +---+---+---+---+---+---+---+---+---+---+---+---+
 |               |                      mac                      |
 +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

## 3. New Login workflow

### Workflow

#### A. Login request (CLIENT)

1. Initiate a `00 00` message

2. Generating with random num generator:

- fresh 6-byte random value `r`
- fresh 32-byte random temp key `tk` -> only be used during authentication process

3. Building MTP message:

- ver = `01 00`
- typ = `00 00`
- len is calculated as the sum of the length of the header (16), the length of the encrypted payload (same as the length of the payload), the length of the mac field (12), and the length of the encrypted temporary key (256)
- sqn = `00 01` (i.e., message sequence numbering is started from 1)
- rnd = r = client_random (i.e., the 6-byte fresh random value generated before)
- rsv = `00 00`

4. Encrypting & signing

- Encrypting the payload of the login request
- Produces an auth tag on message header & encrypted payload:

=> using AES in GCM mode with `tk` as the key and `sqn+rnd` as nonce

Output fields:

- `epd`
- `mac`

5. Encrypts `tk` using RSA-OAEP with RSA pub key

- Produce `etk` = 256 bytes

#### B. Login Response (SERVER)

1. Check the sequence number `sqn` in header

2. Decrypt `etk`

- Takes the last 256 bytes of the message as `etk` + decrypts it using RSA-OAEP with the RSA private key on server

Output: temp key `tk` (generated by client)

3. Verify `mac` & Decryption

- Verify `mac` & decrypt `edp` field using AES in GCM mode with `tk` as the key & `sqn+rnd` as the nonce (obtaining from message header)

4. Build MTP message

Generate a fresh 6-byte random value `r'` = `server_random`

Response look somewaht like:

- ver = `01 00`
- typ = `00 10`
- len is calculated as the sum of the length of the header (16), the length of the encrypted payload (same as the length of the payload), and the length of the mac field (12)
- sqn = `00 01` (i.e., this is the first message from the server to the client)
- rnd = `r'` (i.e., the 6-byte fresh random value generated before)
- rsv = `00 00`

5. Encrypt response:

- Encrypting the payload of the login RESPONSE
- Produces an auth tag on message header & encrypted payload:

=> using AES in GCM mode with `tk` as the key and `sqn+rnd` as nonce

Output fields:

- `epd`
- `mac`

#### After CLIENT receive `server_random` from `SERVER`

**Building 32-byte final transfer key**

- client_random + server_random AND request_hash as salt
- using HKDF key derivation function with SHA-256 as internal hash function

Sequence num -> wont be reset

Producing subsequent MTP messages:

- __Message header__:
  - Appropriate message type (already been implemented. refer: `siftlogin.py/handle_login_server()`, `siftlogin.py/handle_login_client()`)
  - Appropriate length (maybe already been implemented? refer: `siftmpt.py/receive_msg()`)
  - Next sending sequence number
  - Fresh 6-byte random value

- __Payload__: encrypted payload & mac fields => processing message header & payload with AES in GCP mode using `final transfer key` as key and `sqn+rnd` as the nonce
- __sequence num__: incremented sending message sequence number is stored

Receiving a message:

- verifying sequence number sqn in the message is larger than the last received sequence number,
- verifying the mac and decrypts the encrypted payload with AES in GCM mode using the final transfer key as the key and sqn+rnd as the nonce, and
- if all verifications are successful, the stored receiving sequence number is set to the sqn value received in the message header.

A message that DOESNT pass all verifciations will be SILENTLY discarded
-> The connection between client & server must be closed (already been implemented)

### Message Format

> Text-based protocol. UTF-8 encoding

_login_req_

```
<timestamp>'\n'
<username>'\n'
<password>'\n'
<client_random>
```

_login_res_

```
<request_hash>'\n'
<server_random>
```

where

- `<request_hash>` is a hexadecimal number converted to a string, the value of which is the SHA-256 hash of the payload of the login request message converted to a byte string.
- `<server_random>` is a hexadecimal number converted to a string, the value of which is a 16-byte freshly generated random value.
