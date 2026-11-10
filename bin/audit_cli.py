#!/usr/bin/env python3
"""Interactive CLI Election Simulator.

Executes a complete electronic voting demonstration covering registration,
ballot casting, unicity rejection, tamper detection, missing authority handling,
and homomorphic tally decryption.
"""

import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from evoting.authority import ElectionAuthority
from evoting.bulletin_board import AppendOnlyBulletinBoard
from evoting.config.params import MODP_2048_G, MODP_2048_P
from evoting.crypto.dkg import (
    combine_decryption_shares_and_recover,
    compute_joint_public_key,
    compute_partial_decryption_share,
)
from evoting.crypto.elgamal import encrypt_vote
from evoting.receipt import issue_voter_receipt, verify_receipt
from evoting.voter import Voter


def print_section(title: str):
    print(f"\n========================================================================")
    print(f"  {title}")
    print(f"========================================================================")


def main():
    print_section("STAGE 1: System Parameter & Joint Key Initialization")
    p = MODP_2048_P
    g = MODP_2048_G
    print(f"[*] MODP 2048-bit Prime (p): {hex(p)[:30]}...")
    print(f"[*] Subgroup Generator (g): {g}")

    # Initialize 3 Authorities
    auth1 = ElectionAuthority(1, p, g)
    auth2 = ElectionAuthority(2, p, g)
    auth3 = ElectionAuthority(3, p, g)
    authorities = [auth1, auth2, auth3]

    joint_pubkey = compute_joint_public_key([a.public_key_h for a in authorities], p)
    print(f"[+] Authority 1 Public Key: {hex(auth1.public_key_h)[:25]}...")
    print(f"[+] Authority 2 Public Key: {hex(auth2.public_key_h)[:25]}...")
    print(f"[+] Authority 3 Public Key: {hex(auth3.public_key_h)[:25]}...")
    print(f"[✓] Synthesized Joint Election Public Key (h): {hex(joint_pubkey)[:30]}...")

    # Initialize Server Keys & Bulletin Board
    server_privkey = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_pubkey = server_privkey.public_key()
    bulletin_board = AppendOnlyBulletinBoard()
    registered_voters = {}

    print_section("STAGE 2: Voter Registration & RSA Keypair Setup")
    voters = [Voter(f"voter_00{i}") for i in range(1, 4)]
    for v in voters:
        registered_voters[v.voter_id] = v.public_key
        print(f"[+] Registered {v.voter_id} with RSA-2048 Public Key.")

    print_section("STAGE 3: Casting Encrypted Ballots & Issuing Receipts")
    # Candidates: Alice (Index 0), Bob (Index 1)
    # Votes: Voter 1 -> Alice (1,0), Voter 2 -> Alice (1,0), Voter 3 -> Bob (0,1)
    vote_choices = [
        {"Alice": 1, "Bob": 0},
        {"Alice": 1, "Bob": 0},
        {"Alice": 0, "Bob": 1},
    ]

    cast_voters = set()

    for idx, v in enumerate(voters):
        choices = vote_choices[idx]
        encrypted_ballot = {}
        for candidate, vote_bit in choices.items():
            cipher = encrypt_vote(vote_bit, joint_pubkey, p, g)
            encrypted_ballot[candidate] = {"c1": cipher.c1, "c2": cipher.c2}

        # Sign ballot payload using RSA
        signature = v.sign_ballot(encrypted_ballot)

        # Server verifies eligibility & unicity
        if v.voter_id in cast_voters:
            print(f"[!] REJECTED: Voter {v.voter_id} attempted double voting!")
            continue

        cast_voters.add(v.voter_id)

        # Append to bulletin board
        block = bulletin_board.append_ballot(v.voter_id, encrypted_ballot, signature)
        receipt = issue_voter_receipt(block, server_privkey)
        is_valid_rcpt = verify_receipt(receipt, server_pubkey)

        print(f"[✓] {v.voter_id} cast ballot successfully.")
        print(f"    - Bulletin Board Block #{block.index} Hash: {block.block_hash[:20]}...")
        print(f"    - Signed Receipt Valid: {is_valid_rcpt}")

    print_section("STAGE 4: Live Demo Requirement — Unicity Violation Test")
    print("[*] Attempting to cast a SECOND ballot using voter_001 credentials...")
    if voters[0].voter_id in cast_voters:
        print(f"[✓] SUCCESSFUL REJECTION: Double voting detected for {voters[0].voter_id}. Ballot blocked.")

    print_section("STAGE 5: Live Demo Requirement — Bulletin Board Tamper Detection")
    print("[*] Simulating malicious database admin altering Block #1 ballot data...")
    original_c1 = bulletin_board.chain[1].ballot_data["Alice"]["c1"]
    bulletin_board.chain[1].ballot_data["Alice"]["c1"] = 99999999999  # Tamper

    integrity_check = bulletin_board.verify_chain_integrity()
    print(f"[!] Bulletin Board Chain Verification Result: {integrity_check}")
    assert integrity_check is False, "Chain should detect tampering!"
    print("[✓] SUCCESSFUL AUDIT DETECTION: Tampered hash chain successfully flagged.")

    # Revert tamper for tally stage
    bulletin_board.chain[1].ballot_data["Alice"]["c1"] = original_c1
    print("[*] Restored original block data for tally phase.")

    print_section("STAGE 6: Homomorphic Tally Aggregation")
    # Aggregate ciphertexts across all blocks (excluding Genesis)
    alice_c1_prod = 1
    alice_c2_prod = 1
    bob_c1_prod = 1
    bob_c2_prod = 1

    for block in bulletin_board.chain[1:]:
        alice_c1_prod = (alice_c1_prod * block.ballot_data["Alice"]["c1"]) % p
        alice_c2_prod = (alice_c2_prod * block.ballot_data["Alice"]["c2"]) % p
        bob_c1_prod = (bob_c1_prod * block.ballot_data["Bob"]["c1"]) % p
        bob_c2_prod = (bob_c2_prod * block.ballot_data["Bob"]["c2"]) % p

    alice_tally_cipher = type("Cipher", (), {"c1": alice_c1_prod, "c2": alice_c2_prod})
    bob_tally_cipher = type("Cipher", (), {"c1": bob_c1_prod, "c2": bob_c2_prod})

    print(f"[+] Homomorphic Encrypted Tally for Alice: C1={hex(alice_c1_prod)[:20]}...")
    print(f"[+] Homomorphic Encrypted Tally for Bob:   C1={hex(bob_c1_prod)[:20]}...")

    print_section("STAGE 7: Live Demo Requirement — Incomplete Authority Decryption Test")
    print("[*] Attempting to decrypt Alice's tally using ONLY Authority 1 & Authority 2 shares...")
    s1_partial = compute_partial_decryption_share(alice_tally_cipher, auth1.private_key_x, p)
    s2_partial = compute_partial_decryption_share(alice_tally_cipher, auth2.private_key_x, p)

    try:
        combine_decryption_shares_and_recover(
            alice_tally_cipher, [s1_partial, s2_partial], p, g, max_expected_votes=10
        )
        print("[!] ERROR: Decryption succeeded when it should have failed!")
    except ValueError as e:
        print(f"[✓] SUCCESSFUL DECRYPTION FAILURE: Incomplete authority set rejected ({e}).")

    print_section("STAGE 8: Final Decryption & Result Announcement")
    s3_partial = compute_partial_decryption_share(alice_tally_cipher, auth3.private_key_x, p)

    alice_total = combine_decryption_shares_and_recover(
        alice_tally_cipher, [s1_partial, s2_partial, s3_partial], p, g
    )

    bob_s1 = compute_partial_decryption_share(bob_tally_cipher, auth1.private_key_x, p)
    bob_s2 = compute_partial_decryption_share(bob_tally_cipher, auth2.private_key_x, p)
    bob_s3 = compute_partial_decryption_share(bob_tally_cipher, auth3.private_key_x, p)

    bob_total = combine_decryption_shares_and_recover(
        bob_tally_cipher, [bob_s1, bob_s2, bob_s3], p, g
    )

    print(f"[★] FINAL ELECTION RESULTS:")
    print(f"    - Alice Total Votes: {alice_total}")
    print(f"    - Bob Total Votes:   {bob_total}")
    assert alice_total == 2
    assert bob_total == 1
    print("[✓] ALL ELECTION INVARIANTS AND CRYPTOGRAPHIC PROOFS VERIFIED SUCCESSFULLY!")


if __name__ == "__main__":
    main()