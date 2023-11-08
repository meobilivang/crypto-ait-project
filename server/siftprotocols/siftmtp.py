# python3

import socket

from Crypto import Random
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from siftprotocols.utils.crypto import (
    rsa_dec_symkey,
    rsa_enc_symkey,
    aes_dec_symkey,
    aes_enc_symkey,
)


def get_random_bytes(size: int):
    return Random.get_random_bytes(size)


class SiFT_MTP_Error(Exception):
    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_MTP:
    def __init__(self, peer_socket):
        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.version_major = 1
        self.version_minor = 0
        self.msg_hdr_ver = b"\x01\x00"

        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        # v1.0
        self.size_msg_hdr_sqn = 2
        self.size_msg_hdr_rnd = 6
        self.size_msg_hdr_rsv = 2

        # v1.0 login
        self.size_msg_mac = 12
        self.size_msg_etk = 256
        self.size_msg_tk = 32

        self.size_msg_final_transfer_key = 32

        self.type_login_req = b"\x00\x00"
        self.type_login_res = b"\x00\x10"
        self.type_command_req = b"\x01\x00"
        self.type_command_res = b"\x01\x10"
        self.type_upload_req_0 = b"\x02\x00"
        self.type_upload_req_1 = b"\x02\x01"
        self.type_upload_res = b"\x02\x10"
        self.type_dnload_req = b"\x03\x00"
        self.type_dnload_res_0 = b"\x03\x10"
        self.type_dnload_res_1 = b"\x03\x11"
        self.msg_types = (
            self.type_login_req,
            self.type_login_res,
            self.type_command_req,
            self.type_command_res,
            self.type_upload_req_0,
            self.type_upload_req_1,
            self.type_upload_res,
            self.type_dnload_req,
            self.type_dnload_res_0,
            self.type_dnload_res_1,
        )

        # v1.0
        self.rsv = b"\x00\x00"
        # --------- STATE ------------
        self.peer_socket = peer_socket
        # v1.0
        self.sqn = 0
        self.opponent_sqn = 0
        self.client_random = None
        self.server_random = None
        self.tk = None  # for login workflow
        self.final_transfer_key = None

    def increment_sqn(self) -> None:
        self.sqn += 1

    def increment_opponent_sqn(self) -> None:
        self.opponent_sqn += 1

    def compute_final_transfer_key(self, request_hash: bytes) -> None:
        """Compute final transfer key from client_random + server_random using
            request_hash from Login Request as the salt

        Args:
            request_hash (bytes): hash value of Login Request
        """
        k = PBKDF2(
            self.client_random + self.server_random,
            request_hash,
            self.size_msg_final_transfer_key,
            count=100000,
            hmac_hash_module=SHA256,
        )

        # discard client_random & server_random
        self.client_random, self.server_random = None, None

        self.final_transfer_key = k

    # parses a message header and returns a dictionary containing the header fields
    def parse_msg_header(self, msg_hdr):
        """Extract fields from a raw MTP message into a dict

        Returns:
                dict: a dict with all fields from the header of a MTP message
        """

        parsed_msg_hdr, i = {}, 0

        # original from v0.5
        parsed_msg_hdr["ver"], i = (
            msg_hdr[i : i + self.size_msg_hdr_ver],
            i + self.size_msg_hdr_ver,
        )
        parsed_msg_hdr["typ"], i = (
            msg_hdr[i : i + self.size_msg_hdr_typ],
            i + self.size_msg_hdr_typ,
        )
        parsed_msg_hdr["len"], i = (
            msg_hdr[i : i + self.size_msg_hdr_len],
            i + self.size_msg_hdr_len,
        )

        # v1.0
        parsed_msg_hdr["sqn"], i = (
            msg_hdr[i : i + self.size_msg_hdr_sqn],
            i + self.size_msg_hdr_sqn,
        )
        parsed_msg_hdr["rnd"], i = (
            msg_hdr[i : i + self.size_msg_hdr_rnd],
            i + self.size_msg_hdr_rnd,
        )
        parsed_msg_hdr["rsv"], i = (
            msg_hdr[i : i + self.size_msg_hdr_rsv],
            i + self.size_msg_hdr_rsv,
        )

        return parsed_msg_hdr

    # receives n bytes from the peer socket
    def receive_bytes(self, n):
        bytes_received = b""
        bytes_count = 0
        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n - bytes_count)
            except Exception as e:
                raise SiFT_MTP_Error("Unable to receive via peer socket: ", e)
            if not chunk:
                raise SiFT_MTP_Error("Connection with peer is broken")
            bytes_received += chunk
            bytes_count += len(chunk)
        return bytes_received

    # receives and parses message, returns msg_type and msg_payload
    def receive_msg(self):
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error("Unable to receive message header --> " + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error("Incomplete message header received")

        parsed_msg_hdr = self.parse_msg_header(msg_hdr)

        if parsed_msg_hdr["ver"] != self.msg_hdr_ver:
            raise SiFT_MTP_Error("Unsupported version found in message header")

        if parsed_msg_hdr["typ"] not in self.msg_types:
            raise SiFT_MTP_Error("Unknown message type found in message header")

        msg_len = int.from_bytes(parsed_msg_hdr["len"], byteorder="big")

        try:
            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error("Unable to receive message body --> " + e.err_msg)

        # DEBUG
        if self.DEBUG:
            # upon receiving LOGIN REQUEST (for server)
            # at this point, client_random + server_random has
            # not been available on server
            if not self.client_random and not self.server_random:
                print("(Login Request) MTP message received (" + str(msg_len) + "):")
                print("HDR (" + str(len(msg_hdr)) + "): " + msg_hdr.hex())
                print(
                    "EPD ("
                    + str(len(msg_body[: -(self.size_msg_etk + self.size_msg_mac)]))
                    + "): "
                )
                print(msg_body[: -(self.size_msg_etk + self.size_msg_mac)].hex())

                print(
                    "MAC ("
                    + str(
                        len(
                            msg_body[
                                -(
                                    self.size_msg_etk + self.size_msg_mac
                                ) : -self.size_msg_etk
                            ]
                        )
                    )
                    + "): "
                    + msg_body[
                        -(self.size_msg_etk + self.size_msg_mac) : -self.size_msg_etk
                    ].hex()
                )

                print("ETK (" + str(len(msg_body[-self.size_msg_etk :])) + "): ")
                print(msg_body[-self.size_msg_etk :].hex())
                print("------------------------------------------")
            # other cases
            else:
                print("MTP message received (" + str(msg_len) + "):")
                print("HDR (" + str(len(msg_hdr)) + "): " + msg_hdr.hex())
                print("EPD (" + str(len(msg_body[:-12])) + "): ")
                print(msg_body[:-12].hex())
                print("MAC (" + str(len(msg_body[-12:])) + "): " + msg_body[-12:].hex())
                print("------------------------------------------")
        # DEBUG

        # validate message len
        if len(msg_body) != msg_len - self.size_msg_hdr:
            raise SiFT_MTP_Error("Incomplete message body received")

        # validate sqn
        sqn = int.from_bytes(parsed_msg_hdr["sqn"], byteorder="big")
        if sqn <= self.opponent_sqn:
            raise SiFT_MTP_Error("Invalid sequence number")
        self.increment_opponent_sqn()

        # TODO: validate rnd. no rnd collision?

        # validate rsv
        if parsed_msg_hdr["rsv"] != self.rsv:
            raise SiFT_MTP_Error("Invalid rsv byte")

        decrypted_payload = None
        # non-login actions
        if self.final_transfer_key:
            # decrypt + validate MAC with final_transfer_key
            mac = msg_body[-self.size_msg_mac :]  # last 12 bytes
            encrypted_payload = msg_body[
                : -self.size_msg_mac
            ]  # remaining bytes are epd

            decrypted_payload = aes_dec_symkey(
                header=msg_hdr,
                encrypted_payload=encrypted_payload,
                mac=mac,
                aes_symkey=self.final_transfer_key,
                header_sqn=parsed_msg_hdr["sqn"],
                header_rnd=parsed_msg_hdr["rnd"],
            )
        else:
            # special login workflow with extra temp key etk
            # 1. Receiving LOGIN REQUEST (happening on server)
            if not self.server_random and not self.client_random:
                # extract etk & mac
                etk = msg_body[-self.size_msg_etk :]  # last 256 bytes
                mac = msg_body[
                    -(self.size_msg_etk + self.size_msg_mac) : -self.size_msg_etk
                ]  # next 12 bytes after etk
                encrypted_payload = msg_body[
                    : -(self.size_msg_etk + self.size_msg_mac)
                ]  # remaining bytes are epd

                # decrypt etk with private key
                tk = rsa_dec_symkey(enc_aes_symkey=etk)
                self.tk = tk  # save tk for later encryption of SERVER RESPONSE
                # decrypt encrypted payload + verify mac with tk
                decrypted_payload = aes_dec_symkey(
                    header=msg_hdr,
                    encrypted_payload=encrypted_payload,
                    mac=mac,
                    aes_symkey=tk,
                    header_sqn=parsed_msg_hdr["sqn"],
                    header_rnd=parsed_msg_hdr["rnd"],
                )
            # 2. Receiving SERVER RESPONSE (happening on client)
            if self.client_random and not self.server_random:
                # decrypt + validate MAC with tk
                mac = msg_body[-self.size_msg_mac :]  # last 12 bytes
                encrypted_payload = msg_body[
                    : -self.size_msg_mac
                ]  # remaining bytes are epd

                decrypted_payload = aes_dec_symkey(
                    header=msg_hdr,
                    encrypted_payload=encrypted_payload,
                    mac=mac,
                    aes_symkey=self.tk,
                    header_sqn=parsed_msg_hdr["sqn"],
                    header_rnd=parsed_msg_hdr["rnd"],
                )

        return parsed_msg_hdr["typ"], decrypted_payload

    # sends all bytes provided via the peer socket
    def send_bytes(self, bytes_to_send):
        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error("Unable to send via peer socket")

    # builds and sends message of a given type using the provided payload
    def send_msg(
        self, msg_type, msg_payload, tk: bytes | None = None, login: bool = False
    ):
        # build message
        msg_size = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac
        # only LOGIN REQUEST has tk
        if tk and login:
            msg_size += self.size_msg_etk

        msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder="big")

        self.increment_sqn()
        sqn = self.sqn
        msg_hdr_sqn = sqn.to_bytes(self.size_msg_hdr_sqn, byteorder="big")
        msg_hdr_rnd = get_random_bytes(6)
        msg_hdr_rsv = self.rsv

        # v1.0: ver, typ, len, sqn, rnd, rsv
        msg_hdr = (
            self.msg_hdr_ver
            + msg_type
            + msg_hdr_len
            + msg_hdr_sqn
            + msg_hdr_rnd
            + msg_hdr_rsv
        )

        msg_body = None

        # login workflow
        if login:
            # tk is only passed in LOGIN REQUEST
            if tk:
                encrypted_payload, mac = aes_enc_symkey(
                    msg_hdr, msg_payload, tk, msg_hdr_sqn, msg_hdr_rnd
                )
                # save tk to state for later decrypting SERVER RESPONSE
                self.tk = tk
                etk = rsa_enc_symkey(tk)
                # LOGIN REQUEST's body = epd + mac + tk
                msg_body = encrypted_payload + mac + etk
            # LOGIN RESPONSE -> pull tk from state
            else:
                encrypted_payload, mac = aes_enc_symkey(
                    msg_hdr, msg_payload, self.tk, msg_hdr_sqn, msg_hdr_rnd
                )
                msg_body = encrypted_payload + mac
        # other commands
        else:
            encrypted_payload, mac = aes_enc_symkey(
                msg_hdr, msg_payload, self.final_transfer_key, msg_hdr_sqn, msg_hdr_rnd
            )
            msg_body = encrypted_payload + mac

        # DEBUG
        if self.DEBUG:
            # upon sending LOGIN REQUEST (for client)
            # at this point, only client_random is available on client
            if self.client_random and not self.server_random:
                print("(Login Request) MTP message to send (" + str(msg_size) + "):")
                print("HDR (" + str(len(msg_hdr)) + "): " + msg_hdr.hex())
                print(
                    "EPD ("
                    + str(len(msg_body[: -(self.size_msg_etk + self.size_msg_mac)]))
                    + "): "
                )
                print(msg_body[: -(self.size_msg_etk + self.size_msg_mac)].hex())

                print(
                    "MAC ("
                    + str(
                        len(
                            msg_body[
                                -(
                                    self.size_msg_etk + self.size_msg_mac
                                ) : -self.size_msg_etk
                            ]
                        )
                    )
                    + "): "
                    + msg_body[
                        -(self.size_msg_etk + self.size_msg_mac) : -self.size_msg_etk
                    ].hex()
                )

                print("ETK (" + str(len(msg_body[-self.size_msg_etk :])) + "): ")
                print(msg_body[-self.size_msg_etk :].hex())
                print("------------------------------------------")
            else:
                print("MTP message to send (" + str(msg_size) + "):")
                print("HDR (" + str(len(msg_hdr)) + "): " + msg_hdr.hex())
                print("EPD (" + str(len(msg_body[:-12])) + "): ")
                print(msg_body[:-12].hex())
                print("MAC (" + str(len(msg_body[-12:])) + "): " + msg_body[-12:].hex())
                print("------------------------------------------")
        # DEBUG

        # try to send
        try:
            # v1 format: Header + body (= epd + mac)
            self.send_bytes(msg_hdr + msg_body)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error("Unable to send message to peer --> " + e.err_msg)
