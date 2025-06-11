                                                     Ứng dụng Ký số và Xác thực File
![image](https://github.com/user-attachments/assets/b5039b35-36d6-4089-9109-c4da175371c8)
![image](https://github.com/user-attachments/assets/94025e32-8651-4f12-8e4c-3a62f092de75)

🌟 HƯỚNG DẪN SỬ DỤNG ỨNG DỤNG KÝ SỐ VÀ XÁC THỰC FILE 🌟
🔑 1. TẠO CẶP KHÓA MỚI
Bước 1: Nhấn vào nút "Tạo Cặp Khóa Mới".

Bước 2: Hệ thống sẽ tạo và hiển thị:

Private Key (🔒 BÍ MẬT, dùng để ký file).

Public Key (🌍 CÔNG KHAI, dùng để xác thực).

Bước 3: ⚠️ Lưu trữ Private Key ở nơi an toàn (không chia sẻ).

✍️ 2. KÝ SỐ FILE
Bước 1: Chọn file cần ký (📂).

Bước 2: Nhập Private Key (hoặc dùng key vừa tạo).

Bước 3: (Tùy chọn) Nhập email người nhận nếu muốn gửi file.

Bước 4: Nhấn "Tải lên và Ký số".

Kết quả:

✅ File gốc + chữ ký (.sig) + public key (.pub) được lưu.

📧 Nếu có email, hệ thống sẽ gửi file đã ký tự động.

🔍 3. XÁC THỰC CHỮ KÝ
Bước 1: Chọn file cần xác thực (📄).

Bước 2: Chọn file chữ ký (.sig).

Bước 3: Nhập Public Key tương ứng.

Bước 4: Nhấn "Xác thực".

Kết quả:

🟢 "Chữ ký hợp lệ" → File an toàn.

🔴 "Chữ ký không hợp lệ" → Cảnh báo!

📜 4. LỊCH SỬ TẢI LÊN
Danh sách các file đã ký số.

Có thể tải xuống:

📥 File gốc.

📥 File chữ ký (.sig).

📥 Public key (.pub).

🛠 VÍ DỤ VỚI FILE CÓ SẴN
Bạn đã có:

Data.txt (file gốc).

Data.txt.pub (public key).

Data.txt.sig (chữ ký).

Cách kiểm tra:

Tải lên Data.txt.

Tải lên Data.txt.sig.

Copy nội dung Data.txt.pub vào ô Public Key.

Nhấn "Xác thực".

→ Nếu hiện 🟢 "Chữ ký hợp lệ", file đã được ký đúng!

⚠️ LƯU Ý QUAN TRỌNG
Private Key phải được giữ bí mật tuyệt đối.

Mỗi người nên có Private Key riêng.

Public Key có thể chia sẻ tự do.

Luôn kiểm tra chữ ký trước khi sử dụng file.

🚀 CÀI ĐẶT & CHẠY ỨNG DỤNG
Cài đặt thư viện:

bash
pip install -r requirements.txt
Khởi động ứng dụng:

bash
python app.py
Truy cập: http://localhost:5000.

💡 Lưu ý: Để dùng tính năng gửi email, cần cấu hình SMTP trong app.py (dòng 13-14).
