from flask import Flask, request, render_template, send_file, jsonify, send_from_directory
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend
import os
import tempfile
from werkzeug.utils import secure_filename
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import ssl

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Cấu hình email
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'ngoxuanlong2005@gmail.com'  # Thay thế bằng email của bạn
app.config['MAIL_PASSWORD'] = 'kmuw jokt rnnx aimf'  # Thay thế bằng mật khẩu ứng dụng của bạn

# Biến toàn cục để lưu trữ nhật ký
upload_history = []

# Tạo thư mục uploads nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

def sign_file(file_path, private_key_pem):
    """Ký số file sử dụng private key được cung cấp"""
    try:
        # Chuyển đổi private key từ PEM sang đối tượng
        private_key = serialization.load_pem_private_key(
            private_key_pem.encode(),
            password=None,
            backend=default_backend()
        )
        
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
    except Exception as e:
        raise Exception(f"Lỗi khi ký file: {str(e)}")

def verify_signature(file_path, signature, public_key_pem):
    """Xác thực chữ ký sử dụng public key được cung cấp"""
    try:
        # Chuyển đổi public key từ PEM sang đối tượng
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode(),
            backend=default_backend()
        )
        
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
    except Exception as e:
        raise Exception(f"Lỗi khi xác thực: {str(e)}")

def send_signed_file_email(recipient_email, filename, signature_path, public_key):
    """Gửi email chứa file đã ký và public key"""
    try:
        msg = MIMEMultipart()
        msg['From'] = app.config['MAIL_USERNAME']
        msg['To'] = recipient_email
        msg['Subject'] = f'File đã ký số: {filename}'

        # Nội dung email
        body = f"""
        Xin chào,
        
        File {filename} đã được ký số và đính kèm trong email này.
        
        Để xác thực chữ ký, bạn cần:
        1. File gốc (đính kèm)
        2. File chữ ký (đính kèm)
        3. Public key (đính kèm)
        
        Vui lòng truy cập ứng dụng tại http://localhost:5000 để xác thực chữ ký.
        
        Trân trọng,
        Hệ thống Ký số
        """
        msg.attach(MIMEText(body, 'plain'))

        # Đính kèm file gốc
        with open(os.path.join(app.config['UPLOAD_FOLDER'], filename), 'rb') as f:
            file_attachment = MIMEApplication(f.read(), _subtype='octet-stream')
            file_attachment.add_header('Content-Disposition', 'attachment', filename=filename)
            msg.attach(file_attachment)

        # Đính kèm file chữ ký
        with open(signature_path, 'rb') as f:
            sig_attachment = MIMEApplication(f.read(), _subtype='octet-stream')
            sig_attachment.add_header('Content-Disposition', 'attachment', filename=f"{filename}.sig")
            msg.attach(sig_attachment)

        # Đính kèm public key
        key_attachment = MIMEApplication(public_key.encode(), _subtype='octet-stream')
        key_attachment.add_header('Content-Disposition', 'attachment', filename=f"{filename}.pub")
        msg.attach(key_attachment)

        # Gửi email
        context = ssl.create_default_context()
        with smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT']) as server:
            server.starttls(context=context)
            server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
            server.send_message(msg)
        
        return True
    except Exception as e:
        print(f"Lỗi khi gửi email: {str(e)}")
        return False

def generate_key_pair():
    """Tạo cặp khóa RSA mới"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Chuyển đổi private key sang PEM
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    
    # Chuyển đổi public key sang PEM
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    
    return private_key_pem, public_key_pem

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Không tìm thấy file'}), 400
    
    if 'private_key' not in request.form:
        return jsonify({'error': 'Vui lòng nhập private key'}), 400
    
    file = request.files['file']
    private_key_pem = request.form['private_key']
    recipient_email = request.form.get('recipient_email', '')
    
    if file.filename == '':
        return jsonify({'error': 'Không có file được chọn'}), 400

    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)

    try:
        # Ký file với private key được cung cấp
        signature = sign_file(file_path, private_key_pem)

        # Lưu chữ ký
        signature_path = os.path.join(app.config['UPLOAD_FOLDER'], f"{filename}.sig")
        with open(signature_path, 'wb') as f:
            f.write(signature)

        # Thêm vào nhật ký
        upload_history.append({
            'filename': filename,
            'signature_path': signature_path
        })

        # Nếu có email người nhận, gửi file đã ký
        if recipient_email:
            # Tạo public key từ private key
            private_key = serialization.load_pem_private_key(
                private_key_pem.encode(),
                password=None,
                backend=default_backend()
            )
            public_key = private_key.public_key()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            if send_signed_file_email(recipient_email, filename, signature_path, public_key_pem):
                return jsonify({
                    'message': 'File đã được tải lên, ký số và gửi email thành công',
                    'filename': filename
                })
            else:
                return jsonify({
                    'message': 'File đã được tải lên và ký số thành công, nhưng không thể gửi email',
                    'filename': filename
                })

        return jsonify({
            'message': 'File đã được tải lên và ký số thành công',
            'filename': filename
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/verify', methods=['POST'])
def verify_file():
    if 'file' not in request.files or 'signature' not in request.files:
        return jsonify({'error': 'Thiếu file hoặc chữ ký'}), 400
    
    if 'public_key' not in request.form:
        return jsonify({'error': 'Vui lòng nhập public key'}), 400

    file = request.files['file']
    signature = request.files['signature']
    public_key_pem = request.form['public_key']

    # Lưu các file tạm thời
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        file_path = temp_file.name
        file.save(file_path)

    with tempfile.NamedTemporaryFile(delete=False) as temp_sig:
        sig_path = temp_sig.name
        signature.save(sig_path)

    try:
        # Đọc chữ ký
        with open(sig_path, 'rb') as f:
            signature_data = f.read()

        # Xác thực
        is_valid = verify_signature(file_path, signature_data, public_key_pem)

        # Xóa các file tạm
        os.unlink(file_path)
        os.unlink(sig_path)

        return jsonify({
            'valid': is_valid,
            'message': 'Chữ ký hợp lệ' if is_valid else 'Chữ ký không hợp lệ'
        })
    except Exception as e:
        # Xóa các file tạm trong trường hợp lỗi
        try:
            os.unlink(file_path)
            os.unlink(sig_path)
        except:
            pass
        return jsonify({'error': str(e)}), 400

@app.route('/history')
def get_history():
    return jsonify(upload_history)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    try:
        private_key, public_key = generate_key_pair()
        return jsonify({
            'private_key': private_key,
            'public_key': public_key,
            'message': 'Tạo cặp khóa thành công'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(debug=True) 