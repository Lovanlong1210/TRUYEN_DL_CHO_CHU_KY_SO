from flask import Flask, request, render_template, send_file, jsonify, send_from_directory
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import os
import tempfile
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Biến toàn cục để lưu trữ nhật ký
upload_history = []

# Tạo thư mục uploads nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def generate_key_pair():
    """Tạo cặp khóa RSA"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_file(file_path, private_key):
    """Ký số file"""
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    signature = private_key.sign(
        file_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(file_path, signature, public_key):
    """Xác thực chữ ký"""
    with open(file_path, 'rb') as f:
        file_data = f.read()
    
    try:
        public_key.verify(
            signature,
            file_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Không tìm thấy file'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Không có file được chọn'}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    # Tạo cặp khóa và ký file
    private_key, public_key = generate_key_pair()
    signature = sign_file(file_path, private_key)

    # Lưu chữ ký
    signature_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.sig")
    with open(signature_path, 'wb') as f:
        f.write(signature)

    # Lưu public key
    public_key_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.pub")
    with open(public_key_path, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    # Thêm vào nhật ký
    upload_history.append({
        'filename': filename,
        'signature_path': signature_path,
        'public_key_path': public_key_path
    })

    return jsonify({
        'message': 'File đã được tải lên và ký số thành công',
        'filename': filename
    })

@app.route('/verify', methods=['POST'])
def verify_file():
    if 'file' not in request.files or 'signature' not in request.files or 'public_key' not in request.files:
        return jsonify({'error': 'Thiếu file, chữ ký hoặc public key'}), 400

    file = request.files['file']
    signature = request.files['signature']
    public_key_file = request.files['public_key']

    # Lưu các file tạm thời
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        file_path = temp_file.name
        file.save(file_path)

    with tempfile.NamedTemporaryFile(delete=False) as temp_sig:
        sig_path = temp_sig.name
        signature.save(sig_path)

    with tempfile.NamedTemporaryFile(delete=False) as temp_key:
        key_path = temp_key.name
        public_key_file.save(key_path)

    # Đọc public key
    with open(key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )

    # Đọc chữ ký
    with open(sig_path, 'rb') as f:
        signature_data = f.read()

    # Xác thực
    is_valid = verify_signature(file_path, signature_data, public_key)

    # Xóa các file tạm
    os.unlink(file_path)
    os.unlink(sig_path)
    os.unlink(key_path)

    return jsonify({
        'valid': is_valid,
        'message': 'Chữ ký hợp lệ' if is_valid else 'Chữ ký không hợp lệ'
    })

@app.route('/history')
def get_history():
    return jsonify(upload_history)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    app.run(debug=True) 