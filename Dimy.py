# Code completed by Yuchen Bai(z5526405), Shukun Chen(z5466882) and Mengyu You(z5471795)
# Team 5 (Lab: Wed 4-6pm Tutor: Navodika Karunasingha)
import socket
import random
import hashlib
import time
import sys
import threading
import pickle
import secrets
import bitarray
import hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
import numpy as np
import mmh3
import traceback
import struct

# Command line argument parsing
if len(sys.argv) < 4:
    print("Usage: python3 Dimy.py [t] [k] [n] [Server_IP] [Server_Port]")
    print("Example: python3 Dimy.py 15 3 5 127.0.0.1 55000")
    sys.exit(1)

# Parse parameters
t = int(sys.argv[1])  # EphID generation interval (seconds)
k = int(sys.argv[2])  # k value in Shamir secret sharing (requires k shares to reconstruct)
n = int(sys.argv[3])  # Total number of shares generated

# Validate parameters
if t not in [15, 18, 21, 24, 27, 30]:
    print("Error: t must be one of 15, 18, 21, 24, 27, 30")
    sys.exit(1)
if k < 3 or n < 5 or k >= n:
    print("Error: Must satisfy k >= 3, n >= 5 and k < n")
    sys.exit(1)

# Server information
SERVER_IP = sys.argv[4] if len(sys.argv) > 4 else "127.0.0.1"
SERVER_PORT = int(sys.argv[5]) if len(sys.argv) > 5 else 55000

# Node information
NODE_ID = f"Node-{random.randint(1000, 9999)}"
MULTICAST_GROUP = '224.0.0.1'  
MULTICAST_PORT = 50000
BUFFER_SIZE = 4096
BLOOM_FILTER_SIZE = 102400  # 100KB
HASH_FUNCTIONS = 3  # Number of hash functions for Bloom filter

print(f"DIMY node started: {NODE_ID}")
print(f"Parameters: t={t}, k={k}, n={n}")
print(f"Server: {SERVER_IP}:{SERVER_PORT}")

# Global variables
running = True
ephids = {}  
received_shares = {}  
dbfs = []  # Daily Bloom filters
dbf_start_time = time.time()  
current_dbf = bitarray.bitarray(BLOOM_FILTER_SIZE * 8)  
current_dbf.setall(0)
positive_status = False 

# Thread locks
ephids_lock = threading.Lock()
shares_lock = threading.Lock()
dbfs_lock = threading.Lock()

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
    def make_random_shares(secret, minimum, shares, prime=2 ** 521 - 1):
        if minimum > shares:
            raise ValueError("Number of shares must be >= threshold")

        if isinstance(secret, bytes):
            secret_int = int.from_bytes(secret, byteorder='big')
            ephid_byte_len = len(secret)
            byte_length = (prime.bit_length() + 7) // 8
        else:
            raise ValueError("Secret must be bytes")

        poly = [secret_int]
        for _ in range(minimum - 1):
            poly.append(random.randint(0, prime - 1))

        points = []
        for i in range(1, shares + 1):
            x = i
            y_int = ShamirSecretSharing._eval_at(poly, x, prime)
            y_bytes = y_int.to_bytes(byte_length, byteorder='big')
            points.append((x, y_bytes))

        hash_value = hashlib.sha256(secret).hexdigest()
        return points, hash_value, ephid_byte_len

    #     if isinstance(secret, bytes):
    #         secret_int = int.from_bytes(secret, byteorder='big')
    #         byte_length = 40 #len(secret)
    #     else:
    #         secret_int = secret
    #         byte_length = (secret.bit_length() + 7) // 8

    #     poly = [secret_int]
    #     for _ in range(minimum - 1):
    #         poly.append(random.randint(0, prime - 1))

    #     points = []
    #     for i in range(1, shares + 1):
    #         x = i
    #         y = ShamirSecretSharing._eval_at(poly, x, prime)
    #         y_bytes = y.to_bytes(byte_length, byteorder='big')
    #         points.append((x, y_bytes))

    #     hash_value = hashlib.sha256(secret).hexdigest() if isinstance(secret, bytes) else None

    #     return points, hash_value

    @staticmethod
    def reconstruct_secret(shares, original_length, prime=2 ** 521 - 1):
        if len(shares) < 2:
            raise ValueError("Need at least 2 shares to reconstruct")

        byte_length = len(shares[0][1])
        int_shares = [(x, int.from_bytes(y, byteorder='big')) for x, y in shares]

        sums = 0
        for i, (x_i, y_i) in enumerate(int_shares):
            numerator = 1
            denominator = 1
            for j, (x_j, _) in enumerate(int_shares):
                if i == j:
                    continue
                numerator = (numerator * (-x_j)) % prime
                denominator = (denominator * (x_i - x_j)) % prime
            lagrange = (y_i * numerator * pow(denominator, prime - 2, prime)) % prime
            sums = (sums + lagrange) % prime

        reconstructed_bytes = sums.to_bytes(byte_length, byteorder='big')
        return reconstructed_bytes[-original_length:]

class BloomFilter:
    def __init__(self, size, hash_funcs):
        self.size = size
        self.bit_array = bitarray.bitarray(size)
        self.bit_array.setall(0)
        self.hash_funcs = hash_funcs

    def add(self, item):
        for seed in range(self.hash_funcs):
            h = mmh3.hash(item, seed) % self.size
            self.bit_array[h] = 1

    def contains(self, item):
        for seed in range(self.hash_funcs):
            h = mmh3.hash(item, seed) % self.size
            if not self.bit_array[h]:
                return False
        return True

    def merge(self, other):
        if self.size != other.size:
            raise ValueError("Bloom filter size mismatch")
        result = BloomFilter(self.size, self.hash_funcs)
        result.bit_array = self.bit_array | other.bit_array
        return result

    def to_bytes(self):
        return pickle.dumps(self.bit_array)

    @classmethod
    def from_bytes(cls, data, hash_funcs):
        bf = cls(len(pickle.loads(data)), hash_funcs)
        bf.bit_array = pickle.loads(data)
        return bf

def generate_ephid():
    ephid = secrets.token_bytes(32)
    ephid_hash = hashlib.sha256(ephid).hexdigest()

    dh_params = generate_dh_params()
    dh_private_key = generate_dh_private_key(dh_params)
    dh_public_key = generate_dh_public_key(dh_private_key)

    with ephids_lock:
        ephids[ephid_hash] = {
            'ephid': ephid,
            'timestamp': time.time(),
            'shares_sent': 0,
            'dh_params': dh_params,
            'dh_private_key': dh_private_key,
            'dh_public_key': dh_public_key
        }

    shares, hash_value, original_length = ShamirSecretSharing.make_random_shares(ephid, k, n)
    with shares_lock:
        received_shares[ephid_hash] = {
            'shares': [shares[0]],
            'hash': hash_value,
            'length': original_length,
            'reconstructed': False,
            'dh_public_key': serialize_public_key(dh_public_key),
            'node_id': NODE_ID
        }

    print(f"[{time.strftime('%H:%M:%S')}] Generated new EphID: {ephid.hex()[:12]}...")
    return ephid, ephid_hash

# def generate_ephid():
#     ephid = secrets.token_bytes(32)
#     ephid_hash = hashlib.sha256(ephid).hexdigest()

#     with ephids_lock:
#         ephids[ephid_hash] = {
#             'ephid': ephid,
#             'timestamp': time.time(),
#             'shares_sent': 0,
#             'dh_params': generate_dh_params(),
#             'dh_private_key': None,
#             'dh_public_key': None
#         }

#     shares, hash_value, original_length = ShamirSecretSharing.make_random_shares(ephid, k, n)

#     with shares_lock:
#         received_shares[ephid_hash] = {
#             'shares':    [ shares[0] ],
#             'hash':       hash_value,
#             'length':     original_length,
#             'reconstructed': False
#         }
#         ephids[ephid_hash]['dh_private_key'] = generate_dh_private_key(ephids[ephid_hash]['dh_params'])
#         ephids[ephid_hash]['dh_public_key'] = generate_dh_public_key(ephids[ephid_hash]['dh_private_key'])

#     print(f"[{time.strftime('%H:%M:%S')}] Generated new EphID: {ephid.hex()[:12]}...")
#     return ephid, ephid_hash

P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
FFFFFFFF FFFFFFFF
""".replace(" ", "").replace("\n", "")
P_INT = int(P_HEX, 16)
G_INT = 2
DEFAULT_DH_PARAMETERS = dh.DHParameterNumbers(P_INT, G_INT).parameters(default_backend())

def generate_dh_params():
    return DEFAULT_DH_PARAMETERS

def generate_dh_private_key(parameters):
    return parameters.generate_private_key()

def generate_dh_public_key(private_key):
    return private_key.public_key()

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def compute_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(shared_key)
    return digest.finalize()

def broadcast_shares():
    """Broadcast shares of ephemeral IDs using UDP multicast."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)  
    
    while running:
        current_time = time.time()
        with ephids_lock:
            for ephid_hash, data in list(ephids.items()):
                if data['shares_sent'] >= n or positive_status:
                    continue

                ephid = data['ephid']
                if 'shares' not in data:
                    shares, hash_value, original_length = ShamirSecretSharing.make_random_shares(ephid, k, n)
                    data['shares'] = shares
                    data['hash'] = hash_value

                if data['shares_sent'] < len(data['shares']):
                    share_idx = data['shares_sent']
                    share = data['shares'][share_idx]

                    message = {
                        'type': 'share',
                        'node_id': NODE_ID,
                        'ephid_hash': ephid_hash,
                        'share_idx': share_idx,
                        'share': share,
                        'hash': data['hash'],
                        'dh_public_key': serialize_public_key(data['dh_public_key']),
                        'length': original_length
                    }

                    try:
                        # Send to multicast address and port
                        sock.sendto(pickle.dumps(message), (MULTICAST_GROUP, MULTICAST_PORT))
                        print(f"[{time.strftime('%H:%M:%S')}] Sent share {share_idx + 1}/{n} for {ephid.hex()[:12]}")
                        data['shares_sent'] += 1
                    except Exception as e:
                        print(f"Error broadcasting share: {e}")
        time.sleep(3)
    
    if positive_status:
        print(f"[{time.strftime('%H:%M:%S')}] Stopped broadcasting shares due to positive status")
    sock.close()

def listen_for_broadcasts():
    """Listen for multicast shares from other nodes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    # Allow multiple sockets to bind to the same port
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    
    # Bind to the multicast port
    sock.bind(('', MULTICAST_PORT))
    print(f"[{time.strftime('%H:%M:%S')}] Listening on multicast port {MULTICAST_PORT}")
    
    # Join the multicast group
    group = socket.inet_aton(MULTICAST_GROUP)
    mreq = struct.pack('4sL', group, socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    
    while running:
        try:
            data, addr = sock.recvfrom(BUFFER_SIZE)
            message = pickle.loads(data)
            
            if message.get('node_id') == NODE_ID:
                continue
                
            # Simulate 50% message drop
            if random.random() < 0.5:
                print(f"[{time.strftime('%H:%M:%S')}] Dropped message from {message.get('node_id')}")
                continue
                
            if message.get('type') == 'share':
                handle_share_message(message)
                
        except Exception as e:
            print(f"Error receiving broadcast: {e}")
    sock.close()

def handle_share_message(message):
    ephid_hash = message.get('ephid_hash')
    share_idx = message.get('share_idx')
    share = message.get('share')
    hash_value = message.get('hash')
    node_id = message.get('node_id')
    dh_public_key_bytes = message.get('dh_public_key')
    original_length = message.get('length')

    print(f"[{time.strftime('%H:%M:%S')}] Received share {share_idx + 1}/{n} from {node_id}")

    with shares_lock:
        if ephid_hash not in received_shares:
            received_shares[ephid_hash] = {
                'shares': [],
                'hash': hash_value,
                'node_id': node_id,
                'dh_public_key': dh_public_key_bytes,
                'timestamp': time.time(),
                'reconstructed': False,
                'length': original_length
            }
        else:
            if node_id != NODE_ID:
                received_shares[ephid_hash]['dh_public_key'] = dh_public_key_bytes
                received_shares[ephid_hash]['node_id'] = node_id

        existing_xs = [s[0] for s in received_shares[ephid_hash]['shares']]
        if share[0] not in existing_xs:
            received_shares[ephid_hash]['shares'].append(share)
            print(
                f"[{time.strftime('%H:%M:%S')}] Accumulated {len(received_shares[ephid_hash]['shares'])}/{k} shares for {ephid_hash[:12]}")

            if len(received_shares[ephid_hash]['shares']) >= k and not received_shares[ephid_hash]['reconstructed']:
                try:
                    reconstruct_ephid(ephid_hash)
                except Exception as e:
                    print(f"Error reconstructing EphID: {e}")

def reconstruct_ephid(ephid_hash):
    print(f"[{time.strftime('%H:%M:%S')}] 🚨 Attempting to reconstruct EphID: {ephid_hash[:12]}")
    try:
        shares = received_shares[ephid_hash]['shares'][:k]
        original_length = received_shares[ephid_hash]['length']
        shares = sorted(shares, key=lambda x: x[0])
        reconstructed_ephid = ShamirSecretSharing.reconstruct_secret(shares, original_length)
        computed_hash = hashlib.sha256(reconstructed_ephid).hexdigest()

        print(f"[{time.strftime('%H:%M:%S')}] ✅  Reconstructed hash: {computed_hash}")
        print(f"[{time.strftime('%H:%M:%S')}] 🔍 Expected hash:     {ephid_hash}")

        if computed_hash == ephid_hash:
            print(
                f"[{time.strftime('%H:%M:%S')}] 🎯 EphID successfully reconstructed and verified: {reconstructed_ephid.hex()[:12]}")
            received_shares[ephid_hash]['reconstructed'] = True
            received_shares[ephid_hash]['ephid'] = reconstructed_ephid
            compute_encid(ephid_hash)
        else:
            print(f"[{time.strftime('%H:%M:%S')}] ❌  EphID reconstruction failed! Hash mismatch.")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] 🛑 EphID reconstruction error: {e}")

def compute_encid(ephid_hash):
    with shares_lock, ephids_lock:
        if ephid_hash not in received_shares:
            return

        data = received_shares[ephid_hash]
        try:
            peer_public_key_bytes = data['dh_public_key']
            peer_public_key = serialization.load_pem_public_key(peer_public_key_bytes, backend=default_backend())
            peer_numbers = peer_public_key.public_numbers()
            peer_public_key = dh.DHPublicNumbers(peer_numbers.y, dh.DHParameterNumbers(P_INT, G_INT)).public_key(
                default_backend())

            my_params = generate_dh_params()
            my_private_key = generate_dh_private_key(my_params)
            my_public_key = generate_dh_public_key(my_private_key)

            shared_secret = my_private_key.exchange(peer_public_key)
            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(shared_secret)
            encid = digest.finalize()

            print(f"[{time.strftime('%H:%M:%S')}] Calculated EncID: {encid.hex()[:12]} with {data['node_id']}")
            add_to_dbf(encid)
            print(f"[{time.strftime('%H:%M:%S')}] EncID added to DBF and deleted")

        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Error calculating EncID: {e!r}")
            traceback.print_exc()

def add_to_dbf(encid):
    with dbfs_lock:
        encid_hex = encid.hex()
        for i in range(HASH_FUNCTIONS):
            hash_val = mmh3.hash(encid_hex, i) % (BLOOM_FILTER_SIZE * 8)
            current_dbf[hash_val] = 1

        ones_count = current_dbf.count(1)
        print(f"[{time.strftime('%H:%M:%S')}] EncID {encid_hex[:12]} added to current DBF")
        print(f"[{time.strftime('%H:%M:%S')}] Current DBF status: {ones_count}/{BLOOM_FILTER_SIZE * 8} bits set")

def manage_dbfs():
    global current_dbf, dbf_start_time
    rotation_period = t * 6
    max_dbfs = 6

    while running:
        current_time = time.time()
        with dbfs_lock:
            if current_time - dbf_start_time >= rotation_period:
                dbfs.append({
                    'dbf': current_dbf.copy(),
                    'timestamp': dbf_start_time
                })
                print(f"[{time.strftime('%H:%M:%S')}] New DBF created, total DBFs: {len(dbfs)}")

                current_dbf = bitarray.bitarray(BLOOM_FILTER_SIZE * 8)
                current_dbf.setall(0)
                dbf_start_time = current_time

                max_age_seconds = (t * 6 * 6)
                dbfs[:] = [dbf for dbf in dbfs if current_time - dbf['timestamp'] <= max_age_seconds]

                if len(dbfs) > max_dbfs:
                    dbfs[:] = dbfs[-max_dbfs:]

                print(f"[{time.strftime('%H:%M:%S')}] Cleaned DBFs count: {len(dbfs)}")
        time.sleep(1)

def create_qbf():
    dt_seconds = (t * 6 * 6)
    last_qbf_time = time.time()

    while running:
        if positive_status:
            break

        current_time = time.time()
        if current_time - last_qbf_time >= dt_seconds:
            with dbfs_lock:
                if not dbfs and current_dbf.count(1) == 0:
                    print(f"[{time.strftime('%H:%M:%S')}] No data available for QBF")
                    last_qbf_time = current_time
                    continue

                qbf = bitarray.bitarray(BLOOM_FILTER_SIZE * 8)
                qbf.setall(0)

                for dbf_data in dbfs:
                    qbf |= dbf_data['dbf']

                if current_dbf.count(1) > 0:
                    qbf |= current_dbf

                print(
                    f"[{time.strftime('%H:%M:%S')}] Created QBF merging {len(dbfs) + (1 if current_dbf.count(1) > 0 else 0)} DBFs")
                send_qbf_to_server(qbf)
                last_qbf_time = current_time
        time.sleep(10)

def create_cbf():
    global positive_status
    time.sleep(t * 6 + 10)
    print(f"[{time.strftime('%H:%M:%S')}] Simulating COVID-19 positive diagnosis, preparing to upload CBF")

    with dbfs_lock:
        if not dbfs and current_dbf.count(1) == 0:
            print(f"[{time.strftime('%H:%M:%S')}] No data available for CBF")
            return

        cbf = bitarray.bitarray(BLOOM_FILTER_SIZE * 8)
        cbf.setall(0)

        for dbf_data in dbfs:
            cbf |= dbf_data['dbf']

        if current_dbf.count(1) > 0:
            cbf |= current_dbf

        print(
            f"[{time.strftime('%H:%M:%S')}] Created CBF merging {len(dbfs) + (1 if current_dbf.count(1) > 0 else 0)} DBFs")
        send_cbf_to_server(cbf)
        positive_status = True

def send_qbf_to_server(qbf):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))

        message = {
            'type': 'QBF',
            'node_id': NODE_ID,
            'qbf': qbf.tobytes()
        }

        data = pickle.dumps(message)
        data_length = len(data).to_bytes(4, byteorder='big')
        sock.sendall(data_length + data)

        print(f"[{time.strftime('%H:%M:%S')}] ⚡ Sent QBF to server (with {qbf.count(1)} set bits)")

        response = sock.recv(BUFFER_SIZE)
        response_data = pickle.loads(response)

        if response_data.get('match'):
            print(f"[{time.strftime('%H:%M:%S')}] ⚠️ Alert: Possible contact with COVID-19 positive case")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] ✓ Safe: No contacts with positive cases detected")

    except Exception as e:
        print(f"Error sending QBF: {e}")
    finally:
        sock.close()

def send_cbf_to_server(cbf):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((SERVER_IP, SERVER_PORT))

        message = {
            'type': 'CBF',
            'node_id': NODE_ID,
            'cbf': cbf.tobytes()
        }

        data = pickle.dumps(message)
        data_length = len(data).to_bytes(4, byteorder='big')
        sock.sendall(data_length + data)

        print(f"[{time.strftime('%H:%M:%S')}] Sent CBF to server")

        response = sock.recv(BUFFER_SIZE)
        response_data = pickle.loads(response)

        if response_data.get('success'):
            print(
                f"[{time.strftime('%H:%M:%S')}] CBF upload successful, thank you for contributing to pandemic control")
        else:
            print(f"[{time.strftime('%H:%M:%S')}] CBF upload failed: {response_data.get('error')}")

    except Exception as e:
        print(f"Error sending CBF: {e}")
    finally:
        sock.close()

def ephid_generator():
    while running:
        if positive_status:  # 如果节点已报告为阳性，停止生成新的EphID
            print(f"[{time.strftime('%H:%M:%S')}] Node reported positive, stopping EphID generation")
            break
        generate_ephid()
        time.sleep(t)

# Thread management
threads = []
ephid_thread = threading.Thread(target=ephid_generator)
ephid_thread.daemon = True
ephid_thread.start()
threads.append(ephid_thread)

broadcast_thread = threading.Thread(target=broadcast_shares)
broadcast_thread.daemon = True
broadcast_thread.start()
threads.append(broadcast_thread)

listener_thread = threading.Thread(target=listen_for_broadcasts)
listener_thread.daemon = True
listener_thread.start()
threads.append(listener_thread)

dbf_thread = threading.Thread(target=manage_dbfs)
dbf_thread.daemon = True
dbf_thread.start()
threads.append(dbf_thread)

qbf_thread = threading.Thread(target=create_qbf)
qbf_thread.daemon = True
qbf_thread.start()
threads.append(qbf_thread)

cbf_thread = threading.Thread(target=create_cbf)
cbf_thread.daemon = True
cbf_thread.start()
threads.append(cbf_thread)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("Shutting down DIMY client...")
    running = False
    for thread in threads:
        if thread.is_alive():
            thread.join(1)
    print("DIMY client terminated")