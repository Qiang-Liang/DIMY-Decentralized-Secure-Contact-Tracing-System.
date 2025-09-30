# Code completed by Yuchen Bai(z5526405), Shukun Chen(z5466882) and Mengyu You(z5471795)
# Team 5 (Lab: Wed 4-6pm Tutor: Navodika Karunasingha)
import socket
import threading
import pickle
import time
import bitarray
import mmh3
import sys
import os

# Configuration
SERVER_IP = '0.0.0.0'  # Listen on all interfaces
SERVER_PORT = 55000  # Default port
BUFFER_SIZE = 1024 * 1024  # 1MB, accommodates large size Bloom Filters
BLOOM_FILTER_SIZE = 102400  # 100KB
HASH_FUNCTIONS = 3  
MATCH_THRESHOLD = 80

# Global variables
cbfs = []  # List to store Contact Bloom Filters from COVID-19 positive users
cbfs_lock = threading.Lock()  # Lock for thread-safe operations on cbfs
running = True

def check_bloom_filter_match(qbf, cbf):
    """
    Check if a QBF matches any CBF
    Returns True if there's a match, False otherwise
    """
    if isinstance(qbf, bytes):
        qbf_bits = bitarray.bitarray()
        qbf_bits.frombytes(qbf)
    else:
        qbf_bits = qbf

    if isinstance(cbf, bytes):
        cbf_bits = bitarray.bitarray()
        cbf_bits.frombytes(cbf)
    else:
        cbf_bits = cbf

    # A match is detected if intersection of QBF and CBF has any bits set
    intersection = qbf_bits & cbf_bits

    # Calculate match percentage
    bits_in_common = intersection.count(1)
    bits_in_qbf = qbf_bits.count(1)

    # If QBF has no bits set, no match
    if bits_in_qbf == 0:
        return False, 0

    # Calculate match percentage
    match_percentage = (bits_in_common / bits_in_qbf) * 100

    # Consider it a match if at least 80% of QBF bits are in CBF
    # This threshold can be adjusted based on desired false positive/negative rates
    return match_percentage >= MATCH_THRESHOLD, match_percentage

def handle_client(client_socket, client_address):
    """Handle a client connection"""
    print(f"[{time.strftime('%H:%M:%S')}] New connection from {client_address[0]}:{client_address[1]}")

    try:
        # Receive data from client
        # data = client_socket.recv(BUFFER_SIZE)
        # message = pickle.loads(data)
        # Read 4 bytes of length header
        data_length_bytes = b""
        while len(data_length_bytes) < 4:
            chunk = client_socket.recv(4 - len(data_length_bytes))
            if not chunk:
                raise ValueError("Connection interrupted, unable to read complete length header")
            data_length_bytes += chunk

        data_length = int.from_bytes(data_length_bytes, byteorder='big')

        # Receive complete data
        data = b""
        while len(data) < data_length:
            remaining = data_length - len(data)
            chunk = client_socket.recv(min(4096, remaining))
            if not chunk:
                raise ValueError("Connection interrupted, data reception incomplete")
            data += chunk

        # Deserialize message
        message = pickle.loads(data)

        message_type = message.get('type')
        node_id = message.get('node_id')

        print(f"[{time.strftime('%H:%M:%S')}] Received {message_type} from {node_id}")

        if message_type == 'QBF':
            # Handle Query Bloom Filter(QBF)
            qbf_data = message.get('qbf')
            qbf = bitarray.bitarray()
            qbf.frombytes(qbf_data)

            # Check if QBF matches any stored CBF
            match_found = False
            match_percentage = 0

            with cbfs_lock:
                if not cbfs:
                    print(f"[{time.strftime('%H:%M:%S')}] No CBFs available for matching")
                else:
                    for cbf_data in cbfs:
                        is_match, percentage = check_bloom_filter_match(qbf, cbf_data['cbf'])
                        if is_match:
                            match_found = True
                            match_percentage = percentage
                            print(
                                f"[{time.strftime('%H:%M:%S')}] Match found for {node_id} with {percentage:.2f}% similarity")
                            break

            # Send response
            response = {
                'match': match_found,
                'percentage': match_percentage if match_found else 0
            }
            client_socket.sendall(pickle.dumps(response))

            print(
                f"[{time.strftime('%H:%M:%S')}] QBF result sent to {node_id}: {'Match found' if match_found else 'No match'}")

        elif message_type == 'CBF':
            # Handle Contact Bloom Filter(CBF)
            cbf_data = message.get('cbf')

            # Store the CBF
            with cbfs_lock:
                cbfs.append({
                    'node_id': node_id,
                    'cbf': cbf_data,
                    'timestamp': time.time()
                })
                print(f"[{time.strftime('%H:%M:%S')}] Stored CBF from {node_id}. Total CBFs: {len(cbfs)}")

            # Send response
            response = {
                'success': True,
                'message': 'CBF received and stored successfully'
            }
            client_socket.sendall(pickle.dumps(response))

            print(f"[{time.strftime('%H:%M:%S')}] CBF confirmation sent to {node_id}")

        else:
            response = {
                'success': False,
                'error': 'Unknown message type'
            }
            client_socket.sendall(pickle.dumps(response))

    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error handling client {client_address}: {e}")
        try:
            response = {
                'success': False,
                'error': str(e)
            }
            client_socket.sendall(pickle.dumps(response))
        except:
            pass
    finally:
        client_socket.close()
        print(f"[{time.strftime('%H:%M:%S')}] Connection with {client_address[0]}:{client_address[1]} closed")

def clean_old_cbfs():
    """Remove CBFs older than a certain period"""
    global cbfs

    max_age = 14 * 24 * 60 * 60  # 14 DAYS

    while running:
        current_time = time.time()

        with cbfs_lock:
            old_count = len(cbfs)
            cbfs = [cbf for cbf in cbfs if current_time - cbf['timestamp'] <= max_age]
            if old_count != len(cbfs):
                print(f"[{time.strftime('%H:%M:%S')}] Cleaned {old_count - len(cbfs)} old CBFs. Remaining: {len(cbfs)}")

        time.sleep(3600)  

def save_cbfs():
    """Save CBFs to a file periodically"""
    data_dir = "data"
    os.makedirs(data_dir, exist_ok=True)

    while running:
        try:
            with cbfs_lock:
                if cbfs:
                    filename = os.path.join(data_dir, f"cbfs_{int(time.time())}.pickle")
                    with open(filename, "wb") as f:
                        pickle.dump(cbfs, f)
                    print(f"[{time.strftime('%H:%M:%S')}] Saved {len(cbfs)} CBFs to {filename}")
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] Error saving CBFs: {e}")

        time.sleep(3600)  

def load_cbfs():
    """Load CBFs from the most recent file"""
    global cbfs

    data_dir = "data"
    os.makedirs(data_dir, exist_ok=True)

    try:
        # Find the most recent CBF file
        files = [os.path.join(data_dir, f) for f in os.listdir(data_dir) if
                 f.startswith("cbfs_") and f.endswith(".pickle")]
        if files:
            latest_file = max(files, key=os.path.getmtime)
            with open(latest_file, "rb") as f:
                loaded_cbfs = pickle.load(f)
                with cbfs_lock:
                    cbfs = loaded_cbfs
                print(f"[{time.strftime('%H:%M:%S')}] Loaded {len(cbfs)} CBFs from {latest_file}")
    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Error loading CBFs: {e}")

def statistics_reporter():
    """Report statistics periodically"""
    while running:
        with cbfs_lock:
            print(f"[{time.strftime('%H:%M:%S')}] Server Statistics:")
            print(f"  - CBFs stored: {len(cbfs)}")
            print(f"  - Matching threshold: {MATCH_THRESHOLD}%")
            if cbfs:
                oldest = min([cbf['timestamp'] for cbf in cbfs])
                oldest_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(oldest))
                print(f"  - Oldest CBF: {oldest_date}")

        time.sleep(300)  

def main():
    global SERVER_PORT, running

    if len(sys.argv) > 1:
        SERVER_PORT = int(sys.argv[1])

    print(f"[{time.strftime('%H:%M:%S')}] DIMY Backend Server starting on port {SERVER_PORT}")
    print(f"[{time.strftime('%H:%M:%S')}] QBF-CBF matching threshold set to {MATCH_THRESHOLD}%")

    # Load existing CBFs
    load_cbfs()

    # Create TCP socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server_socket.bind((SERVER_IP, SERVER_PORT))
        server_socket.listen(5)
        print(f"[{time.strftime('%H:%M:%S')}] Server listening on {SERVER_IP}:{SERVER_PORT}")

        # Start maintenance threads
        cleanup_thread = threading.Thread(target=clean_old_cbfs)
        cleanup_thread.daemon = True
        cleanup_thread.start()

        save_thread = threading.Thread(target=save_cbfs)
        save_thread.daemon = True
        save_thread.start()

        stats_thread = threading.Thread(target=statistics_reporter)
        stats_thread.daemon = True
        stats_thread.start()

        # Main server loop
        while running:
            try:
                client_socket, client_address = server_socket.accept()
                client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()

            except KeyboardInterrupt:
                print("\n[{time.strftime('%H:%M:%S')}] Server shutdown initiated...")
                running = False
                break
            except Exception as e:
                print(f"[{time.strftime('%H:%M:%S')}] Error accepting connection: {e}")

    except Exception as e:
        print(f"[{time.strftime('%H:%M:%S')}] Server error: {e}")
    finally:
        server_socket.close()
        print(f"[{time.strftime('%H:%M:%S')}] Server socket closed")

if __name__ == "__main__":
    main()