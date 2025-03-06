#!/usr/bin/env python3
# Venym AI - Solana Vanity Wallet Generator
# Created by Venym AI (venym.io)
# Contact: t.me/venymlobby | x.com/venymai
import threading
import concurrent.futures
import time
import os
from nacl.signing import SigningKey
import base58

# Global counter and lock for progress reporting
total_generated = 0
counter_lock = threading.Lock()

def worker(pattern_front: str, pattern_back: str, match_type: str, case_sensitive: bool, stop_event: threading.Event):
    global total_generated
    while not stop_event.is_set():
        # Generate a new key pair (ed25519) using PyNaCl
        sk = SigningKey.generate()
        vk = sk.verify_key
        pubkey_bytes = vk.encode()
        address = base58.b58encode(pubkey_bytes).decode('utf-8')

        # Update the global counter
        with counter_lock:
            total_generated += 1

        # Normalize strings if not case sensitive
        check_address = address if case_sensitive else address.lower()
        pattern_front_norm = pattern_front if case_sensitive else pattern_front.lower()
        pattern_back_norm = pattern_back if case_sensitive else pattern_back.lower()

        # Check pattern based on match type
        if match_type == "front":
            if not pattern_front or check_address.startswith(pattern_front_norm):
                stop_event.set()
                return sk, vk, address
        elif match_type == "back":
            if not pattern_back or check_address.endswith(pattern_back_norm):
                stop_event.set()
                return sk, vk, address
        elif match_type == "both":
            if ((not pattern_front or check_address.startswith(pattern_front_norm)) and 
                (not pattern_back or check_address.endswith(pattern_back_norm))):
                stop_event.set()
                return sk, vk, address
        elif match_type == "any":
            # "any" means the pattern must appear at the front or the end
            if not pattern_front or check_address.startswith(pattern_front_norm) or check_address.endswith(pattern_front_norm):
                stop_event.set()
                return sk, vk, address
    return None

def progress_reporter(stop_event: threading.Event, start_time: float):
    # Reports progress every 2 seconds
    while not stop_event.is_set():
        time.sleep(2)
        with counter_lock:
            current_count = total_generated
        elapsed = time.time() - start_time
        rate = current_count / elapsed if elapsed > 0 else 0
        print(f"[{elapsed:.2f}s] Keys generated: {current_count}, Rate: {rate:.2f} keys/sec")
    with counter_lock:
        current_count = total_generated
    elapsed = time.time() - start_time
    rate = current_count / elapsed if elapsed > 0 else 0
    print(f"Final: [{elapsed:.2f}s] Keys generated: {current_count}, Rate: {rate:.2f} keys/sec")

def main():
    print("Venym AI - Solana Vanity Wallet Generator")
    print("Powered by Venym AI - venym.io")
    print("------------------------------------------")
    
    # Ask for the desired matching type
    while True:
        match_type = input("Where do you want the pattern to match? (front/back/both/any): ").strip().lower()
        if match_type in {"front", "back", "both", "any"}:
            break
        else:
            print("Please enter 'front', 'back', 'both', or 'any'.")
    
    # Get the desired pattern(s) based on the chosen match type
    if match_type in {"front", "back"}:
        pattern = input(f"Enter the desired pattern for the {match_type} of the wallet address: ")
        pattern_front = pattern if match_type == "front" else ""
        pattern_back = pattern if match_type == "back" else ""
    elif match_type == "both":
        same = input("Do you want the same pattern for both ends? (y/n): ").strip().lower()
        if same == "y":
            pattern = input("Enter the desired pattern: ")
            pattern_front = pattern
            pattern_back = pattern
        else:
            pattern_front = input("Enter the desired pattern for the front: ")
            pattern_back = input("Enter the desired pattern for the back: ")
    elif match_type == "any":
        pattern = input("Enter the desired pattern (will be matched if it is at the front or at the end): ")
        pattern_front = pattern  # reusing this for "any" matching
        pattern_back = ""

    cs_input = input("Should the matching be case sensitive? (y/n): ").strip().lower()
    case_sensitive = (cs_input == 'y')

    print("\nStarting vanity wallet generation...")
    num_threads = os.cpu_count() or 4
    print(f"Using {num_threads} threads. This might take a while...")

    stop_event = threading.Event()
    start_time = time.time()

    # Start the progress reporter thread
    progress_thread = threading.Thread(target=progress_reporter, args=(stop_event, start_time))
    progress_thread.start()

    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(worker, pattern_front, pattern_back, match_type, case_sensitive, stop_event)
                   for _ in range(num_threads)]
        result = None
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is not None:
                break

    stop_event.set()
    progress_thread.join()

    if result is not None:
        sk, vk, address = result
        elapsed = time.time() - start_time
        print(f"\nFound matching wallet in {elapsed:.2f} seconds!")
        print(f"Wallet Address: {address}")
        # Create the full 64-byte secret key (32 bytes secret + 32 bytes public)
        full_secret = sk.encode() + vk.encode()
        # Convert the full secret key to a Base58 encoded string (this is the format Phantom accepts)
        private_key_b58 = base58.b58encode(full_secret).decode('utf-8')
        print("Private Key (Base58 format, keep this safe!):")
        print(private_key_b58)

if __name__ == "__main__":
    main()
