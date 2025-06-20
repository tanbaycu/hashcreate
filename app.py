from flask import Flask, render_template, request, jsonify, send_file
import hashlib
import bcrypt
import hmac
import base64
import secrets
import zlib
import binascii
import struct
import time
import json
import os
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
import argon2
from io import BytesIO
import csv
from user_agents import parse
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# PostgreSQL Database Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:HGqklGJDDbkyfdzvUxlTnHKwGkXUYLHB@caboose.proxy.rlwy.net:21273/railway'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,
    'pool_recycle': 300,
    'connect_args': {"sslmode": "require"}
}

db = SQLAlchemy(app)

# Database Models
class HashResult(db.Model):
    __tablename__ = 'hash_results'
    
    id = db.Column(db.Integer, primary_key=True)
    original_text = db.Column(db.Text, nullable=False)
    hash_value = db.Column(db.Text, nullable=False)
    hash_type = db.Column(db.String(50), nullable=False)
    salt = db.Column(db.String(255))
    iterations = db.Column(db.Integer)
    processing_time = db.Column(db.Float)
    strength_score = db.Column(db.Integer)
    strength_level = db.Column(db.String(20))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(500))
    ip_address = db.Column(db.String(50))

class FileHash(db.Model):
    __tablename__ = 'file_hashes'
    
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, nullable=False)
    hash_value = db.Column(db.Text, nullable=False)
    hash_type = db.Column(db.String(50), nullable=False)
    processing_time = db.Column(db.Float)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(500))
    ip_address = db.Column(db.String(50))

class BatchHash(db.Model):
    __tablename__ = 'batch_hashes'
    
    id = db.Column(db.Integer, primary_key=True)
    batch_id = db.Column(db.String(50), nullable=False)
    total_processed = db.Column(db.Integer, nullable=False)
    total_time = db.Column(db.Float, nullable=False)
    average_time = db.Column(db.Float, nullable=False)
    hash_type = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(500))
    ip_address = db.Column(db.String(50))

class BenchmarkResult(db.Model):
    __tablename__ = 'benchmark_results'
    
    id = db.Column(db.Integer, primary_key=True)
    algorithm = db.Column(db.String(50), nullable=False)
    total_time = db.Column(db.Float, nullable=False)
    hashes_per_second = db.Column(db.Float, nullable=False)
    iterations = db.Column(db.Integer, nullable=False)
    test_text = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    user_agent = db.Column(db.String(500))
    ip_address = db.Column(db.String(50))

# Initialize database tables
def init_db():
    """Initialize database tables if they don't exist"""
    try:
        db.create_all()
        print("Database tables initialized successfully!")
    except Exception as e:
        print(f"Error initializing database tables: {e}")

# Initialize database tables immediately
with app.app_context():
    init_db()

# No longer need uploads folder - using database storage

def crc32_hash(data):
    """Tính CRC32 checksum"""
    return format(zlib.crc32(data.encode()) & 0xffffffff, '08x')

def adler32_hash(data):
    """Tính Adler32 checksum"""
    return format(zlib.adler32(data.encode()) & 0xffffffff, '08x')

def fnv1_hash(data):
    """FNV-1 hash implementation"""
    fnv_prime = 16777619
    fnv_offset_basis = 2166136261
    
    hash_value = fnv_offset_basis
    for byte in data.encode():
        hash_value = (hash_value * fnv_prime) % (2**32)
        hash_value = hash_value ^ byte
    
    return format(hash_value, '08x')

def fnv1a_hash(data):
    """FNV-1a hash implementation"""
    fnv_prime = 16777619
    fnv_offset_basis = 2166136261
    
    hash_value = fnv_offset_basis
    for byte in data.encode():
        hash_value = hash_value ^ byte
        hash_value = (hash_value * fnv_prime) % (2**32)
    
    return format(hash_value, '08x')

def djb2_hash(data):
    """DJB2 hash algorithm"""
    hash_value = 5381
    for char in data:
        hash_value = ((hash_value << 5) + hash_value) + ord(char)
        hash_value = hash_value & 0xffffffff
    return format(hash_value, '08x')

def sdbm_hash(data):
    """SDBM hash algorithm"""
    hash_value = 0
    for char in data:
        hash_value = ord(char) + (hash_value << 6) + (hash_value << 16) - hash_value
        hash_value = hash_value & 0xffffffff
    return format(hash_value, '08x')

def simple_checksum(data):
    """Simple checksum"""
    return format(sum(data.encode()) & 0xffffffff, '08x')

def rot13_encode(data):
    """ROT13 encoding"""
    result = ""
    for char in data:
        if 'a' <= char <= 'z':
            result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z':
            result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else:
            result += char
    return result

def base85_encode(data):
    """Base85 encoding"""
    try:
        return base64.b85encode(data.encode()).decode()
    except:
        return base64.b64encode(data.encode()).decode()

def analyze_hash_strength(hash_value, hash_type):
    """Phân tích độ mạnh của hash"""
    strength = {
        'score': 0,
        'level': 'Weak',
        'recommendations': []
    }
    
    # Scoring based on hash type
    security_scores = {
        'md5': 1, 'sha1': 2, 'sha224': 3, 'sha256': 4, 'sha384': 5, 'sha512': 5,
        'sha3_224': 4, 'sha3_256': 5, 'sha3_384': 5, 'sha3_512': 5,
        'blake2b': 5, 'blake2s': 4, 'bcrypt': 5, 'argon2': 5, 'scrypt': 5,
        'pbkdf2_sha256': 4, 'pbkdf2_sha512': 5
    }
    
    base_score = security_scores.get(hash_type, 2)
    strength['score'] = min(base_score * 20, 100)
    
    if strength['score'] >= 80:
        strength['level'] = 'Very Strong'
    elif strength['score'] >= 60:
        strength['level'] = 'Strong'
    elif strength['score'] >= 40:
        strength['level'] = 'Medium'
    else:
        strength['level'] = 'Weak'
    
    # Recommendations
    if hash_type in ['md5', 'sha1']:
        strength['recommendations'].append('Consider using SHA-256 or better')
    if hash_type not in ['bcrypt', 'argon2', 'scrypt'] and 'password' in hash_value.lower():
        strength['recommendations'].append('Use bcrypt/Argon2 for passwords')
    
    return strength

def benchmark_hash_performance(text, hash_type, iterations=1000):
    """Benchmark hash performance"""
    start_time = time.time()
    
    for _ in range(iterations):
        if hash_type == 'sha256':
            hashlib.sha256(text.encode()).hexdigest()
        elif hash_type == 'md5':
            hashlib.md5(text.encode()).hexdigest()
        elif hash_type == 'bcrypt':
            bcrypt.hashpw(text.encode(), bcrypt.gensalt())
            break  # bcrypt is slow, only do once
    
    end_time = time.time()
    total_time = end_time - start_time
    
    if hash_type == 'bcrypt':
        hashes_per_second = 1 / total_time
    else:
        hashes_per_second = iterations / total_time
    
    return {
        'total_time': round(total_time * 1000, 2),  # ms
        'hashes_per_second': round(hashes_per_second, 2),
        'iterations': 1 if hash_type == 'bcrypt' else iterations
    }

@app.errorhandler(404)
def not_found_error(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500

@app.route('/health')
def health_check():
    """Health check endpoint"""
    try:
        # Test database connection
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.utcnow().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

@app.route('/')
def index():
    user_agent = request.headers.get('User-Agent')
    ua = parse(user_agent)
    
    # Detect mobile devices
    if ua.is_mobile or ua.is_tablet:
        return render_template('mobile.html')
    else:
        return render_template('index.html')

@app.route('/generate_hash', methods=['POST'])
def generate_hash():
    try:
        data = request.json
        text = data.get('text', '')
        hash_type = data.get('hash_type', 'md5')
        salt = data.get('salt', '')
        iterations = data.get('iterations', 10000)
        
        if not text:
            return jsonify({'error': 'Text is required'}), 400
        
        start_time = time.time()
        result = {}
        
        # Basic Hash Algorithms
        if hash_type == 'md5':
            result['hash'] = hashlib.md5(text.encode()).hexdigest()
        elif hash_type == 'sha1':
            result['hash'] = hashlib.sha1(text.encode()).hexdigest()
        elif hash_type == 'sha224':
            result['hash'] = hashlib.sha224(text.encode()).hexdigest()
        elif hash_type == 'sha256':
            result['hash'] = hashlib.sha256(text.encode()).hexdigest()
        elif hash_type == 'sha384':
            result['hash'] = hashlib.sha384(text.encode()).hexdigest()
        elif hash_type == 'sha512':
            result['hash'] = hashlib.sha512(text.encode()).hexdigest()
        # SHA-3 Family
        elif hash_type == 'sha3_224':
            result['hash'] = hashlib.sha3_224(text.encode()).hexdigest()
        elif hash_type == 'sha3_256':
            result['hash'] = hashlib.sha3_256(text.encode()).hexdigest()
        elif hash_type == 'sha3_384':
            result['hash'] = hashlib.sha3_384(text.encode()).hexdigest()
        elif hash_type == 'sha3_512':
            result['hash'] = hashlib.sha3_512(text.encode()).hexdigest()
        # SHAKE
        elif hash_type == 'shake_128':
            result['hash'] = hashlib.shake_128(text.encode()).hexdigest(32)
        elif hash_type == 'shake_256':
            result['hash'] = hashlib.shake_256(text.encode()).hexdigest(64)
        # BLAKE Family
        elif hash_type == 'blake2b':
            result['hash'] = hashlib.blake2b(text.encode()).hexdigest()
        elif hash_type == 'blake2s':
            result['hash'] = hashlib.blake2s(text.encode()).hexdigest()
        # Password Hashing
        elif hash_type == 'bcrypt':
            hashed = bcrypt.hashpw(text.encode(), bcrypt.gensalt())
            result['hash'] = hashed.decode()
        elif hash_type == 'pbkdf2_sha256':
            if not salt:
                salt = secrets.token_hex(16)
            hashed = hashlib.pbkdf2_hmac('sha256', text.encode(), salt.encode(), iterations)
            result['hash'] = base64.b64encode(hashed).decode()
            result['salt'] = salt
            result['iterations'] = iterations
        elif hash_type == 'pbkdf2_sha512':
            if not salt:
                salt = secrets.token_hex(16)
            hashed = hashlib.pbkdf2_hmac('sha512', text.encode(), salt.encode(), iterations)
            result['hash'] = base64.b64encode(hashed).decode()
            result['salt'] = salt
            result['iterations'] = iterations
        elif hash_type == 'argon2':
            result['hash'] = argon2.hash_password(text.encode()).decode()
        elif hash_type == 'scrypt':
            if not salt:
                salt = secrets.token_hex(16)
            hashed = hashlib.scrypt(text.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=64)
            result['hash'] = base64.b64encode(hashed).decode()
            result['salt'] = salt
        # HMAC Family
        elif hash_type == 'hmac_md5':
            if not salt:
                salt = secrets.token_hex(16)
            hashed = hmac.new(salt.encode(), text.encode(), hashlib.md5).hexdigest()
            result['hash'] = hashed
            result['key'] = salt
        elif hash_type == 'hmac_sha1':
            if not salt:
                salt = secrets.token_hex(16)
            hashed = hmac.new(salt.encode(), text.encode(), hashlib.sha1).hexdigest()
            result['hash'] = hashed
            result['key'] = salt
        elif hash_type == 'hmac_sha256':
            if not salt:
                salt = secrets.token_hex(16)
            hashed = hmac.new(salt.encode(), text.encode(), hashlib.sha256).hexdigest()
            result['hash'] = hashed
            result['key'] = salt
        elif hash_type == 'hmac_sha512':
            if not salt:
                salt = secrets.token_hex(16)
            hashed = hmac.new(salt.encode(), text.encode(), hashlib.sha512).hexdigest()
            result['hash'] = hashed
            result['key'] = salt
        # Checksum Algorithms
        elif hash_type == 'crc32':
            result['hash'] = crc32_hash(text)
        elif hash_type == 'adler32':
            result['hash'] = adler32_hash(text)
        elif hash_type == 'simple_checksum':
            result['hash'] = simple_checksum(text)
        # Non-cryptographic Hash Functions
        elif hash_type == 'fnv1':
            result['hash'] = fnv1_hash(text)
        elif hash_type == 'fnv1a':
            result['hash'] = fnv1a_hash(text)
        elif hash_type == 'djb2':
            result['hash'] = djb2_hash(text)
        elif hash_type == 'sdbm':
            result['hash'] = sdbm_hash(text)
        # Encoding Methods
        elif hash_type == 'base64':
            result['hash'] = base64.b64encode(text.encode()).decode()
        elif hash_type == 'base32':
            result['hash'] = base64.b32encode(text.encode()).decode()
        elif hash_type == 'base16':
            result['hash'] = base64.b16encode(text.encode()).decode()
        elif hash_type == 'base85':
            result['hash'] = base85_encode(text)
        elif hash_type == 'url_safe_base64':
            result['hash'] = base64.urlsafe_b64encode(text.encode()).decode()
        # Classic Ciphers
        elif hash_type == 'rot13':
            result['hash'] = rot13_encode(text)
        elif hash_type == 'hex':
            result['hash'] = text.encode().hex()
        elif hash_type == 'ascii':
            result['hash'] = ' '.join(str(ord(c)) for c in text)
        elif hash_type == 'binary':
            result['hash'] = ' '.join(format(ord(c), '08b') for c in text)
        else:
            return jsonify({'error': 'Unsupported hash type'}), 400
        
        end_time = time.time()
        processing_time = round((end_time - start_time) * 1000, 2)
        
        result['original'] = text
        result['type'] = hash_type
        result['length'] = len(result['hash'])
        result['processing_time'] = processing_time
        result['timestamp'] = int(time.time())
        
        # Add hash strength analysis
        result['strength'] = analyze_hash_strength(result['hash'], hash_type)
        
        # Save to database
        try:
            hash_record = HashResult(
                original_text=text,
                hash_value=result['hash'],
                hash_type=hash_type,
                salt=result.get('salt'),
                iterations=result.get('iterations'),
                processing_time=processing_time,
                strength_score=result['strength']['score'],
                strength_level=result['strength']['level'],
                user_agent=request.headers.get('User-Agent'),
                ip_address=request.remote_addr
            )
            db.session.add(hash_record)
            db.session.commit()
            result['record_id'] = hash_record.id
        except Exception as e:
            print(f"Error saving to database: {e}")
            # Continue without failing the request
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/batch_hash', methods=['POST'])
def batch_hash():
    try:
        data = request.json
        texts = data.get('texts', [])
        hash_type = data.get('hash_type', 'sha256')
        
        if not texts:
            return jsonify({'error': 'No texts provided'}), 400
        
        results = []
        start_time = time.time()
        
        for i, text in enumerate(texts):
            if not text.strip():
                continue
                
            # Generate hash for each text
            hash_result = generate_single_hash(text.strip(), hash_type)
            hash_result['index'] = i + 1
            results.append(hash_result)
        
        end_time = time.time()
        total_time = round((end_time - start_time) * 1000, 2)
        
        batch_result = {
            'results': results,
            'total_processed': len(results),
            'total_time': total_time,
            'average_time': round(total_time / len(results), 2) if results else 0
        }
        
        # Save batch info to database
        try:
            batch_id = secrets.token_hex(8)
            batch_record = BatchHash(
                batch_id=batch_id,
                total_processed=len(results),
                total_time=total_time,
                average_time=round(total_time / len(results), 2) if results else 0,
                hash_type=hash_type,
                user_agent=request.headers.get('User-Agent'),
                ip_address=request.remote_addr
            )
            db.session.add(batch_record)
            db.session.commit()
            batch_result['batch_id'] = batch_id
        except Exception as e:
            print(f"Error saving batch hash to database: {e}")
        
        return jsonify(batch_result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def generate_single_hash(text, hash_type):
    """Generate hash for a single text"""
    result = {}
    
    if hash_type == 'md5':
        result['hash'] = hashlib.md5(text.encode()).hexdigest()
    elif hash_type == 'sha256':
        result['hash'] = hashlib.sha256(text.encode()).hexdigest()
    elif hash_type == 'sha512':
        result['hash'] = hashlib.sha512(text.encode()).hexdigest()
    else:
        result['hash'] = hashlib.sha256(text.encode()).hexdigest()  # default
    
    result['original'] = text
    result['type'] = hash_type
    result['length'] = len(result['hash'])
    
    return result

@app.route('/upload_file', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        hash_type = request.form.get('hash_type', 'sha256')
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content
        file_content = file.read()
        
        start_time = time.time()
        
        # Generate hash based on type
        if hash_type == 'md5':
            hash_value = hashlib.md5(file_content).hexdigest()
        elif hash_type == 'sha1':
            hash_value = hashlib.sha1(file_content).hexdigest()
        elif hash_type == 'sha256':
            hash_value = hashlib.sha256(file_content).hexdigest()
        elif hash_type == 'sha512':
            hash_value = hashlib.sha512(file_content).hexdigest()
        else:
            hash_value = hashlib.sha256(file_content).hexdigest()
        
        end_time = time.time()
        processing_time = round((end_time - start_time) * 1000, 2)
        
        result = {
            'filename': file.filename,
            'size': len(file_content),
            'hash': hash_value,
            'type': hash_type,
            'processing_time': processing_time,
            'timestamp': int(time.time())
        }
        
        # Save to database
        try:
            file_hash_record = FileHash(
                filename=file.filename,
                file_size=len(file_content),
                hash_value=hash_value,
                hash_type=hash_type,
                processing_time=processing_time,
                user_agent=request.headers.get('User-Agent'),
                ip_address=request.remote_addr
            )
            db.session.add(file_hash_record)
            db.session.commit()
            result['record_id'] = file_hash_record.id
        except Exception as e:
            print(f"Error saving file hash to database: {e}")
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/compare_hashes', methods=['POST'])
def compare_hashes():
    try:
        data = request.json
        hash1 = data.get('hash1', '').strip()
        hash2 = data.get('hash2', '').strip()
        
        if not hash1 or not hash2:
            return jsonify({'error': 'Both hashes are required'}), 400
        
        # Compare hashes
        is_match = hash1.lower() == hash2.lower()
        
        # Analyze differences if not matching
        differences = []
        if not is_match:
            for i, (c1, c2) in enumerate(zip(hash1.lower(), hash2.lower())):
                if c1 != c2:
                    differences.append({
                        'position': i,
                        'hash1_char': c1,
                        'hash2_char': c2
                    })
        
        return jsonify({
            'match': is_match,
            'hash1_length': len(hash1),
            'hash2_length': len(hash2),
            'differences': differences[:10],  # Limit to first 10 differences
            'total_differences': len(differences)
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/export_results', methods=['POST'])
def export_results():
    try:
        data = request.json
        results = data.get('results', [])
        format_type = data.get('format', 'json')
        
        if not results:
            return jsonify({'error': 'No results to export'}), 400
        
        if format_type == 'json':
            output = BytesIO()
            output.write(json.dumps(results, indent=2).encode())
            output.seek(0)
            
            return send_file(
                output,
                mimetype='application/json',
                as_attachment=True,
                download_name='hash_results.json'
            )
        
        elif format_type == 'csv':
            output = BytesIO()
            writer = csv.writer(output.getvalue().decode().splitlines())
            
            # Write header
            if results:
                headers = list(results[0].keys())
                writer.writerow(headers)
                
                # Write data
                for result in results:
                    writer.writerow([result.get(h, '') for h in headers])
            
            output.seek(0)
            return send_file(
                output,
                mimetype='text/csv',
                as_attachment=True,
                download_name='hash_results.csv'
            )
        
        else:
            return jsonify({'error': 'Unsupported format'}), 400
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/benchmark', methods=['POST'])
def benchmark():
    try:
        data = request.json
        text = data.get('text', 'benchmark test')
        algorithms = data.get('algorithms', ['md5', 'sha256', 'sha512'])
        
        results = []
        
        for algo in algorithms:
            try:
                perf = benchmark_hash_performance(text, algo)
                perf['algorithm'] = algo
                results.append(perf)
                
                # Save benchmark result to database
                try:
                    benchmark_record = BenchmarkResult(
                        algorithm=algo,
                        total_time=perf['total_time'],
                        hashes_per_second=perf['hashes_per_second'],
                        iterations=perf['iterations'],
                        test_text=text,
                        user_agent=request.headers.get('User-Agent'),
                        ip_address=request.remote_addr
                    )
                    db.session.add(benchmark_record)
                    db.session.commit()
                except Exception as db_error:
                    print(f"Error saving benchmark to database: {db_error}")
                    
            except Exception as e:
                results.append({
                    'algorithm': algo,
                    'error': str(e)
                })
        
        return jsonify({'benchmarks': results})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/verify_hash', methods=['POST'])
def verify_hash():
    try:
        data = request.json
        text = data.get('text', '')
        hash_value = data.get('hash', '')
        hash_type = data.get('hash_type', 'bcrypt')
        
        if hash_type == 'bcrypt':
            is_valid = bcrypt.checkpw(text.encode(), hash_value.encode())
            return jsonify({'valid': is_valid})
            
        elif hash_type == 'argon2':
            try:
                argon2.verify_password(hash_value.encode(), text.encode())
                return jsonify({'valid': True})
            except:
                return jsonify({'valid': False})
        
        return jsonify({'error': 'Verification not supported for this hash type'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history', methods=['GET'])
def get_hash_history():
    """Lấy lịch sử hash"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        hash_type = request.args.get('hash_type')
        
        query = HashResult.query
        if hash_type:
            query = query.filter_by(hash_type=hash_type)
        
        paginated = query.order_by(HashResult.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        results = []
        for item in paginated.items:
            results.append({
                'id': item.id,
                'original_text': item.original_text[:50] + '...' if len(item.original_text) > 50 else item.original_text,
                'hash_value': item.hash_value,
                'hash_type': item.hash_type,
                'strength_level': item.strength_level,
                'processing_time': item.processing_time,
                'created_at': item.created_at.isoformat()
            })
        
        return jsonify({
            'results': results,
            'total': paginated.total,
            'page': page,
            'per_page': per_page,
            'pages': paginated.pages
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/file_history', methods=['GET'])
def get_file_hash_history():
    """Lấy lịch sử hash file"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        paginated = FileHash.query.order_by(FileHash.created_at.desc()).paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        results = []
        for item in paginated.items:
            results.append({
                'id': item.id,
                'filename': item.filename,
                'file_size': item.file_size,
                'hash_value': item.hash_value,
                'hash_type': item.hash_type,
                'processing_time': item.processing_time,
                'created_at': item.created_at.isoformat()
            })
        
        return jsonify({
            'results': results,
            'total': paginated.total,
            'page': page,
            'per_page': per_page,
            'pages': paginated.pages
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Lấy thống kê sử dụng"""
    try:
        # Thống kê tổng quan
        total_hashes = HashResult.query.count()
        total_files = FileHash.query.count()
        total_batches = BatchHash.query.count()
        total_benchmarks = BenchmarkResult.query.count()
        
        # Thống kê theo hash type
        hash_type_stats = db.session.query(
            HashResult.hash_type,
            db.func.count(HashResult.id).label('count')
        ).group_by(HashResult.hash_type).all()
        
        # Thống kê theo strength level
        strength_stats = db.session.query(
            HashResult.strength_level,
            db.func.count(HashResult.id).label('count')
        ).group_by(HashResult.strength_level).all()
        
        return jsonify({
            'totals': {
                'hashes': total_hashes,
                'files': total_files,
                'batches': total_batches,
                'benchmarks': total_benchmarks
            },
            'hash_types': [{'type': item[0], 'count': item[1]} for item in hash_type_stats],
            'strength_levels': [{'level': item[0], 'count': item[1]} for item in strength_stats]
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export_db', methods=['GET'])
def export_database():
    """Export dữ liệu từ database"""
    try:
        export_type = request.args.get('type', 'hash')
        format_type = request.args.get('format', 'json')
        
        if export_type == 'hash':
            results = HashResult.query.all()
            data = []
            for item in results:
                data.append({
                    'id': item.id,
                    'original_text': item.original_text,
                    'hash_value': item.hash_value,
                    'hash_type': item.hash_type,
                    'salt': item.salt,
                    'iterations': item.iterations,
                    'processing_time': item.processing_time,
                    'strength_score': item.strength_score,
                    'strength_level': item.strength_level,
                    'created_at': item.created_at.isoformat(),
                    'user_agent': item.user_agent,
                    'ip_address': item.ip_address
                })
        elif export_type == 'file':
            results = FileHash.query.all()
            data = []
            for item in results:
                data.append({
                    'id': item.id,
                    'filename': item.filename,
                    'file_size': item.file_size,
                    'hash_value': item.hash_value,
                    'hash_type': item.hash_type,
                    'processing_time': item.processing_time,
                    'created_at': item.created_at.isoformat(),
                    'user_agent': item.user_agent,
                    'ip_address': item.ip_address
                })
        else:
            return jsonify({'error': 'Invalid export type'}), 400
        
        if format_type == 'json':
            output = BytesIO()
            output.write(json.dumps(data, indent=2, ensure_ascii=False).encode('utf-8'))
            output.seek(0)
            
            return send_file(
                output,
                mimetype='application/json',
                as_attachment=True,
                download_name=f'{export_type}_results.json'
            )
        
        return jsonify({'error': 'Unsupported format'}), 400
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Chạy trên tất cả IP addresses để có thể truy cập từ mạng LAN
    app.run(host='0.0.0.0', port=5000, debug=True)
