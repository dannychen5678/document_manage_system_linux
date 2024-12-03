import logging
from flask import request, render_template, redirect, url_for, Blueprint, flash, session, send_file, make_response, jsonify, current_app
import json
from app import db
from functools import wraps
from .models import Document, Forward, User, Attachment
from app.utils import (
    create_digital_signature_combined,
    verify_signature_combined,
    decrypt_private_key,
    generate_aes_key,
    encrypt_with_aes,
    encrypt_aes_key,
    decrypt_aes_key,
    decrypt_with_aes,
    generate_keys,
    encrypt_private_key
)
from cryptography.hazmat.primitives import serialization
from werkzeug.utils import secure_filename
from PyPDF2 import PdfReader
from docx import Document as DocxDocument
from datetime import datetime
import os
import secrets
import base64
import rsa  # 添加這一行
main = Blueprint("main", __name__)
ALLOWED_EXTENSIONS = {'txt','pdf','docx'}
UPLOAD_FOLDER = os.path.join(os.getcwd(),'app','static','upload')
DOCUMENT_FOLDER = os.path.join(UPLOAD_FOLDER, 'documents')  # 公文主檔
ATTACHMENT_FOLDER = os.path.join(UPLOAD_FOLDER, 'attachments')  # 附件資料夾
FORWARDED_FILES = {}  # 記錄轉發的文件
SIGNED_FILES = {}  # 記錄簽署的文件

DEPARTMENT_MAPPING = {
    'principal': '校長室',
    'academic affairs': '教務處',
    'student affairs': '學務處',
    'general affairs': '總務處',
    'secretariat': '秘書室',
    'accounting': '主計室',
    'personnel': '人事室',
    'research': '研發處',
    'extension': '進修推廣部',
    'library': '圖資館',
    'engineering': '海洋工程學院',
    'management': '人文管理學院',
    'tourism': '觀光休閒學院'
}

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin', False):
            flash('您沒有權限訪問此頁面')
            return redirect(url_for('main.index'))
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("請先登入。")
            return redirect(url_for('main.login'))
        return f(*args, **kwargs)
    return decorated_function

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def ensure_directory_exists(directory):
    """確保指定的目錄存在，如果不存在則創建它"""
    if not os.path.exists(directory):
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"Created directory: {directory}")
        except Exception as e:
            print(f"Error creating directory {directory}: {str(e)}")
            raise

# 在應用初始化時調用
@main.before_app_request
def setup_folders():
    ensure_directory_exists(UPLOAD_FOLDER)
    ensure_directory_exists(DOCUMENT_FOLDER)
    ensure_directory_exists(ATTACHMENT_FOLDER)

def get_department_display_name(department_code):
    department_mapping = DEPARTMENT_MAPPING
    return department_mapping.get(department_code, department_code)

# 收文夾
@main.route('/index', methods=['GET'])
@login_required
def index():
    user_id = session.get('user_id')
    if not user_id:  # 檢查用戶是否已登入
        flash("請先登入")
        return redirect(url_for('main.login'))
    
    user = User.query.get(user_id)  # 獲取用戶信息
    
    # 獲取當前用戶需要處理的公文
    pending_documents = Document.query.filter_by(
        current_handler_id=user_id,
        status='待簽核'
    ).order_by(Document.created_at.desc()).all()
    
    # 獲取當前用戶已處理的公文
    processed_documents = db.session.query(Document)\
        .join(Forward)\
        .filter(
            Forward.user_id == user_id,
            Forward.status.in_(['已簽核', '退件'])
        )\
        .order_by(Document.created_at.desc())\
        .all()
    
    for doc in processed_documents:
        doc.forward = Forward.query.filter_by(
            document_id=doc.id,
            user_id=user_id
        ).first()
    
    # 獲取當前用戶建立的公文
    created_documents = Document.query.filter_by(
        creator_id=user_id
    ).order_by(Document.created_at.desc()).all()
    
    response = make_response(render_template('index.html',
        pending_documents=pending_documents,
        processed_documents=processed_documents,
        created_documents=created_documents,
        user=user
    ))
    
    return response

# 用戶註冊路由
@main.route("/register", methods=["GET", "POST"])
@login_required
@admin_required
def register():
    user_id = session.get('user_id')
    
    user = User.query.get(user_id)

    if request.method == "POST":
        username = request.form["username"]
        department = request.form["department"]  # 新增部門字段
        account = request.form["account"]
        password = request.form["password"]
        email = request.form["email"]
        is_admin = 'is_admin' in request.form  # 檢查是否選擇了系統管理員

        # 檢查用戶名是否已存在
        existing_user = User.query.filter_by(account=account).first()
        if existing_user:
            flash("帳號已存在，請選擇其他帳號。")
            return redirect(url_for('main.register'))

        # 生成密鑰
        private_key_pem, public_key_pem = generate_keys()

        # 添加這裡，打印生成的私鑰和公鑰
        print(f"Generated Private Key: {private_key_pem}")
        print(f"Generated Public Key: {public_key_pem}")

        # 創建新用戶，並保存公鑰/私鑰額外保存
        new_user = User(
            username=username,
            department=department,  # 保存部門信息
            account=account,
            email=email,
            public_key=public_key_pem,  # 保存公鑰
            is_admin=is_admin,  # 設置用戶角色
            force_password_change=True  # 設置為需要強制修改密碼
        )
        #密碼加密
        new_user.set_password(password)
        #私鑰加密
        new_user.set_encrypted_private_key(private_key_pem, encrypt_private_key)
        try:
            db.session.add(new_user)
            db.session.commit()
            flash("註冊成功，請登入。")
            return redirect(url_for('main.login'))
        except Exception as e:
            db.session.rollback()
            flash(f"註冊失敗：{str(e)}")
            return redirect(url_for('main.register'))

    return render_template("register.html", account=user.account)  # 渲染註冊頁面
@main.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form["email"]
        user = User.query.filter_by(email=email).first()
        if user:
            # 生成一個隨機的重置令牌
            reset_token = secrets.token_urlsafe(32)
            user.reset_token = reset_token
            db.session.commit()
            
            # 這裡應該發送一封包含重置鏈接的郵件
            # 為了演示，我們只是打印出重置鏈接
            reset_link = url_for('main.reset_password', token=reset_token, _external=True)
            print(f"重置密碼鏈接: {reset_link}")
            
            flash("重置密碼的說明已發送到您的郵箱。")
            return redirect(url_for('main.login'))
        else:
            flash("找不到與該郵箱關聯的帳戶。")
    return render_template("forgot_password.html")

@main.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    user = User.query.filter_by(reset_token=token).first()
    if not user:
        flash("無效或過期的重置令牌。")
        return redirect(url_for('main.login'))
    
    if request.method == "POST":
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        
        if new_password != confirm_password:
            flash("新密碼和確認密碼不匹配。")
            return redirect(url_for('main.reset_password', token=token))
        
        user.set_password(new_password)
        user.reset_token = None  # 清除重置令牌
        db.session.commit()
        flash("密碼已成功重置。請使用新密碼登入。")
        return redirect(url_for('main.login'))
    
    return render_template("reset_password.html", token=token)

@main.route("/dashboard", methods=["GET"])
@login_required
@admin_required
def dashboard():
    return render_template("dashboard.html")

# 登入畫面
@main.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        account = request.form["account"]
        password = request.form["password"]        

        user = User.query.filter_by(account=account).first()

        if user and user.check_password(password):
            session['user_id'] = user.id
            session['account'] = user.account
            session['is_admin'] = user.is_admin

            if user.force_password_change:
                flash('首次登入請修改密碼')
                return redirect(url_for('main.change_password'))

            if user.is_admin:
                return redirect(url_for('main.dashboard'))
            return redirect(url_for('main.index'))

        flash("帳號或密碼錯誤")
        return redirect(url_for('main.login'))

    return render_template("login.html")

@main.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("您已成功登出。")
    return redirect(url_for('main.login'))

@main.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user_id = session.get('user_id')
    user = User.query.get(user_id)

    if request.method == "POST":
        old_password = request.form.get("old_password")
        new_password = request.form.get("new_password")
        confirm_password = request.form.get("confirm_password")

        # 檢查舊密碼是否正確
        if not user.check_password(old_password):
            flash("舊密碼不正確")
            return redirect(url_for('main.change_password'))

        # 檢查新密碼和確認密碼是否匹配
        if new_password != confirm_password:
            flash("新密碼與確認密碼不符")
            return redirect(url_for('main.change_password'))

        # 更新密碼
        user.set_password(new_password)
        user.force_password_change = False
        db.session.commit()
        flash("密碼修改成功")
        
        # 如果是強制修改密碼，修改成功後重定向到首頁
        if user.force_password_change:
            return redirect(url_for('main.index'))
        # 否則返回個人資料頁面
        return redirect(url_for('main.profile'))

    return render_template("change_password.html", username=user.username)  # 傳遞使用者名稱

@main.route('/find', methods=['GET'])
@login_required  # 確保用戶已登入
def find():
    return render_template('find.html')

@main.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'GET':
        # 生成文號：年份+月份+流水號
        current_date = datetime.now()
        year = current_date.year
        month = str(current_date.month).zfill(2)
        
        latest_doc = Document.query.filter(
            Document.number.like(f'{year}{month}%')
        ).order_by(Document.number.desc()).first()
        
        if latest_doc and latest_doc.number:
            serial = str(int(latest_doc.number[-4:]) + 1).zfill(4)
        else:
            serial = '0001'
            
        document_number = f'{year}{month}{serial}'
        users = User.query.filter(User.id != session['user_id']).all()
        return render_template('upload.html', 
                               document_number=document_number,
                               users=users,
                               department_mapping=DEPARTMENT_MAPPING)
    
    elif request.method == 'POST':
        document_path = None
        attachment_paths = []
        try:
            # 確保上傳目錄存在
            upload_base = os.path.join(current_app.root_path, 'static', 'upload')
            documents_dir = os.path.join(upload_base, 'documents')
            
            ensure_directory_exists(upload_base)
            ensure_directory_exists(documents_dir)

            # 驗證必要欄位
            required_fields = ['document_number', 'documentType', 'subject', 
                               'deadline', 'urgency', 'classification']
            for field in required_fields:
                if field not in request.form:
                    raise ValueError(f'缺少必要欄位: {field}')
            
            # 驗證主文件
            if 'document' not in request.files:
                raise ValueError('未找到上傳文件')
            
            document_file = request.files['document']
            if not document_file or not document_file.filename:
                raise ValueError('未選擇文件')
            
            if not allowed_file(document_file.filename):
                raise ValueError('不支援的文件格式')
            
            # 處理主文件
            original_filename = document_file.filename
            if '.' not in original_filename:
                raise ValueError('文件必須包含副檔名')
                
            file_extension = original_filename.rsplit('.', 1)[1].lower()
            document_number = request.form.get('document_number')
            
            custom_filename = request.form.get('documentFileName', '').strip()
            if custom_filename:
                filename = f"{document_number}_{custom_filename}.{file_extension}"
            else:
                base_name = original_filename.rsplit('.', 1)[0]
                filename = f"{document_number}_{base_name}.{file_extension}"
            
            filename = secure_filename(filename)
            document_path = os.path.join(documents_dir, filename)
            
            # 保存文件
            document_file.save(document_path)
            with open(document_path, 'rb') as f:
                content_bytes = f.read()

            signature_message = request.form.get('signature_message', '').strip()
            
            # 獲取當前用戶的私鑰並解密
            current_user = User.query.get(session['user_id'])
            private_key = decrypt_private_key(current_user.private_key_encrypted)

             # 初始化加密日誌
            encryption_log = {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'sender': current_user.username,
                'encryption_steps': []
            }
            
          
             # 創建初始簽章（前一次簽章為空）
            initial_signature = create_digital_signature_combined(
                content=content_bytes,
                signature_message=signature_message,
                private_key_pem=private_key,
                previous_signature=""
            )
            encryption_log['encryption_steps'].append({
                'step': '創建數位簽章',
                'status': '成功',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })

              # 立即驗證初始簽章
            is_valid = verify_signature_combined(
                content=content_bytes,
                signature=initial_signature,
                public_key_pem=current_user.public_key,
                signature_message=signature_message,
                previous_signature=""
            )
            if not is_valid:
                raise ValueError("初始簽章驗證失敗，文件可能已被篡改")
            encryption_log['encryption_steps'].append({
                'step': '驗證數位簽章',
                'status': '成功',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })

                  # 保存加密日誌到 session
            session['last_encryption_log'] = encryption_log
            # 處理受文者
            recipients_data = request.form.get('recipients')
            if not recipients_data:
                raise ValueError('必須選擇至少一個受文者')
            recipients = json.loads(recipients_data)
            first_recipient = recipients[0]

            # 獲取第一個收文者的資訊ex.公鑰
            first_recipient_user = User.query.get(first_recipient['id'])
             # 記錄加密過程
            encryption_log = {
                'time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'sender': current_user.username,
                'recipient': first_recipient_user.username,
                'encryption_steps': [],
                'public_key_used': first_recipient_user.public_key[:50] + '...',  # 只顯示部分公鑰
                'document_info': {
                    'number': request.form['document_number'],
                    'subject': request.form['subject']
                }
            }

            if not first_recipient_user.public_key:
                raise ValueError('收文者未設置公鑰')

            # 生成 AES 密鑰並加密內容
            aes_key = generate_aes_key()
            encryption_log['encryption_steps'].append({
                'step': '生成AES密鑰',
                'status': '成功',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })

            encrypted_content = encrypt_with_aes(content_bytes, aes_key)
            encryption_log['encryption_steps'].append({
                'step': '使用AES密鑰加密文件內容',
                'status': '成功',
                'timestamp': datetime.now().strftime('%H:%M:%S')
            })

            # 使用收文者的公鑰加密 AES 密鑰
            encrypted_aes_key = encrypt_aes_key(aes_key, first_recipient_user.public_key)
            encryption_log['encryption_steps'].append({
                'step': '使用接收者公鑰加密AES密鑰',
                'status': '成功',
                'timestamp': datetime.now().strftime('%H:%M:%S'),
                'recipient_public_key_used': True
            })
            
            session['last_encryption_log'] = encryption_log
            
            # 創建文件記錄
            document = Document(
                number=request.form['document_number'],
                type=request.form['documentType'],
                subject=request.form['subject'],
                description=request.form.get('description', ''),
                deadline=datetime.strptime(request.form['deadline'], '%Y-%m-%d'),
                status='待簽核',
                urgency=request.form['urgency'],
                classification=request.form['classification'],
                creator_id=session['user_id'],
                file_path=filename,
                current_handler_id=first_recipient['id'],
                current_order=1,
                initial_signature=initial_signature,
                initial_signature_message=signature_message,
                encrypted_content=encrypted_content,
                encrypted_aes_key=encrypted_aes_key,
                current_encryption_user_id=first_recipient['id'],
                encryption_log=json.dumps(encryption_log)  # 保存加密日誌
            )
            
            db.session.add(document)
            db.session.flush()

            # 處理附件
            attachments_dir = os.path.join(current_app.root_path, 'static', 'upload', 'attachments')
            ensure_directory_exists(attachments_dir)

            attachments = request.files.getlist('attachment')
            attachment_descriptions = request.form.getlist('attachmentDescription')
            
            for i, attachment_file in enumerate(attachments):
                if attachment_file and attachment_file.filename:
                    if not allowed_file(attachment_file.filename):
                        raise ValueError(f'不支援的附件格式: {attachment_file.filename}')
                    
                    original_filename = attachment_file.filename
                    attachment_filename = f"{document_number}_attachment_{secrets.token_hex(4)}_{original_filename}"
                    attachment_path = os.path.join(attachments_dir, attachment_filename)
                    
                    try:
                        attachment_file.save(attachment_path)
                        attachment_paths.append(attachment_path)
                        
                        attachment_description = attachment_descriptions[i] if i < len(attachment_descriptions) else ''
                        attachment = Attachment(
                            document_id=document.id,
                            filename=attachment_filename,
                            file_path=os.path.join('attachments', attachment_filename),
                            description=attachment_description
                        )
                        db.session.add(attachment)
                        
                    except Exception as e:
                        raise ValueError(f'保存附件時出錯: {str(e)}')

            # 創建轉發記錄
            for recipient in recipients:
                forward = Forward(
                    document_id=document.id,
                    user_id=recipient['id'],
                    order=recipient['order'],
                    status='待簽核' if recipient['order'] == 1 else '未處理'
                )
                db.session.add(forward)

            # 添加決行者
            approver_id = request.form.get('approver')
            if approver_id:
                final_order = len(recipients) + 1
                forward = Forward(
                    document_id=document.id,
                    user_id=approver_id,
                    order=final_order,
                    is_approver=True,
                    status='未處理'
                )
                db.session.add(forward)

            db.session.commit()
            return jsonify({'status': 'success', 'encryption_log': encryption_log})

        except Exception as e:
            db.session.rollback()
            if document_path and os.path.exists(document_path):
                try:
                    os.remove(document_path)
                except Exception as cleanup_error:
                    print(f"Error cleaning up file: {cleanup_error}")

            for path in attachment_paths:
                if os.path.exists(path):
                    try:
                        os.remove(path)
                    except Exception as cleanup_error:
                        print(f"Error cleaning up attachment: {cleanup_error}")
            
            return jsonify({'status': 'error', 'message': str(e)}), 400

@main.route('/sign/<int:doc_id>', methods=['GET', 'POST'])
@login_required
def sign(doc_id):
    try:
        document = Document.query.get_or_404(doc_id)
        user_id = session.get('user_id')
        user = User.query.get(user_id)
        creator = User.query.get(document.creator_id)
       # 查找上一個已簽核的處理人
        previous_forward = Forward.query.filter_by(
            document_id=doc_id,
            status='已簽核'
        ).order_by(Forward.order.desc()).first()

         # 確定加密用戶
        if previous_forward:
            # 如果有前一個處理人，使用他的資訊
            encryption_user = User.query.get(previous_forward.user_id)
        else:
            # 如果沒有前一個處理人，使用創建者的資訊
            encryption_user = creator

        # 添加加密解密過程的記錄
        encryption_log = {
            'encrypted_aes_key': document.encrypted_aes_key[:50] + '...',  # 只顯示部分加密的AES密鑰
            'current_handler': user.username,
            'encryption_user': encryption_user.username,  # 這裡會顯示上一個處理人或創建者
            'decryption_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
     
        # 解密 AES 密鑰以獲取文件內容
        try:
            decrypted_aes_key = decrypt_aes_key(
                document.encrypted_aes_key,
                user.get_decrypted_private_key(decrypt_private_key)
            )
            encryption_log['decryption_status'] = '成功'
            
            decrypted_content = decrypt_with_aes(
                document.encrypted_content,
                decrypted_aes_key
            )
            encryption_log['content_decryption'] = '成功'

        except Exception as e:
            flash('文件解密失敗')
            print(f"文件解密錯誤: {str(e)}")
            return redirect(url_for('main.index'))
        
        previous_forwards = Forward.query.filter_by(
            document_id=doc_id,
            status='已簽核'
        ).order_by(Forward.order).all()

       # 首先驗證文件創建者的初始簽章
        try:
            is_valid = verify_signature_combined(
                content=decrypted_content, # 原始文件內容
                signature=document.initial_signature,  # 創建者的簽章
                public_key_pem=creator.public_key, # 創建者的公鑰
                signature_message=document.initial_signature_message,# 創建者的簽核意見
                previous_signature="" # 因為是第一個簽章，所以沒有前一個簽章
            )   
        except Exception as e:
            flash(f'警告：{creator.username} 的初始簽章驗證失敗，文件可能已被篡改')
            return redirect(url_for('main.index'))
        
        # 使用創建者的初始簽章作為起點，驗證後續每個處理人的簽章
        previous_signature = document.initial_signature# 從創建者的簽章開始
        for forward in previous_forwards: # 依序驗證每個處理人的簽章
            signer = User.query.get(forward.user_id)
            is_valid = verify_signature_combined(
                content=decrypted_content,   # 原始文件內容
                signature=forward.signature,    # 當前處理人的簽章
                public_key_pem=signer.public_key, # 當前處理人的公鑰
                signature_message=forward.signature_message, # 當前處理人的簽核意見
                previous_signature=previous_signature# 前一個人的簽章
            )
            if not is_valid:
                flash(f'警告：{signer.username} 的簽章驗證失敗，文件可能已被篡改')
                return redirect(url_for('main.index'))
            previous_signature = forward.signature

        if document.current_handler_id != user_id:
            flash('您目前無權處理此公文')
            return redirect(url_for('main.index'))

        if request.method == 'POST':
            try:
                action = request.form.get('action')
                signature_message = request.form.get('signature_message')

                if not action or not signature_message:
                    return jsonify({
                        'status': 'error',
                        'message': '缺少必要參數'
                    }), 400

                # 獲取當前處理人的簽核記錄
                current_forward = Forward.query.filter_by(
                    document_id=doc_id,
                    user_id=user_id,
                    status='待簽核'
                ).first()

                if not current_forward:
                    return jsonify({
                        'status': 'error',
                        'message': '找不到對應的簽核記錄'
                    }), 404

                # 解密私鑰
                try:
                    if not user.private_key_encrypted:
                        print("用戶私鑰未設置")
                        return jsonify({
                            'status': 'error',
                            'message': '用戶私鑰未設置'
                        }), 500
                        
                    print(f"加密的私鑰: {user.private_key_encrypted[:50]}...")
                    private_key = user.get_decrypted_private_key(decrypt_private_key)
                    print("私鑰解密成功")
                    
                except Exception as e:
                    print(f"私鑰解密詳細錯誤: {str(e)}")
                    return jsonify({
                        'status': 'error',
                        'message': f'私鑰解密失敗: {str(e)}'
                    }), 500

                # 使用方式一創建數位簽章
                try:
                   # 1. 查找最後一個已簽核的記錄
                    previous_forward_for_new_signature = Forward.query.filter_by(
                        document_id=doc_id, # 當前文件
                        status='已簽核' # 狀態為已簽核
                    ).order_by(Forward.order.desc()).first()# 按順序降序排列並取第一個（即最後簽核的）
                    
                    # 如果有前一個簽核，使用其簽章；如果沒有，使用創建者的初始簽章
                    previous_signature_for_new = (
                        previous_forward_for_new_signature.signature # 如果有人簽過，用最後一個人的簽章
                        if previous_forward_for_new_signature     # 條件判斷：是否有人簽過
                        else document.initial_signature         # 如果沒人簽過，用創建者的初始簽章
                    )
                    
                    if not decrypted_content:
                        print("文件內容未設置")
                        return jsonify({
                            'status': 'error',
                            'message': '文件內容未設置'
                        }), 500
                        
                    print("開始創建數位簽章")
                    new_signature = create_digital_signature_combined(
                        content=decrypted_content,
                        signature_message=signature_message,
                        private_key_pem=private_key,
                        previous_signature=previous_signature_for_new
                    )
                    print("數位簽章創建成功")
                    
                except Exception as e:
                    print(f"簽章創建詳細錯誤: {str(e)}")
                    return jsonify({
                        'status': 'error',
                        'message': f'簽章創建失敗: {str(e)}'
                    }), 500

                # 更新簽核記錄
                try:
                    current_forward.status = '已簽核' if action == 'approve' else '退件'
                    current_forward.signature = new_signature
                    current_forward.signature_message = signature_message
                    current_forward.signature_date = datetime.now()

                    # 更新文件狀態
                    if action == 'approve':
                        next_forward = Forward.query.filter_by(
                            document_id=doc_id,
                            order=document.current_order + 1
                        ).first()

                        if next_forward:
                            # 為下一個處理人重新加密文件
                            next_user = User.query.get(next_forward.user_id)
                            if not next_user.public_key:
                                raise ValueError('下一個處理人未設置公鑰')

                            new_aes_key = generate_aes_key()
                            new_encrypted_content = encrypt_with_aes(decrypted_content, new_aes_key)
                            new_encrypted_aes_key = encrypt_aes_key(new_aes_key, next_user.public_key)

                            document.encrypted_content = new_encrypted_content
                            document.encrypted_aes_key = new_encrypted_aes_key
                            document.current_encryption_user_id = next_user.id
                            document.current_handler_id = next_user.id
                            document.current_order += 1
                            document.status = '待簽核'
                            next_forward.status = '待簽核'
                        else:
                            document.status = '已結案'
                            document.current_handler_id = None
                    else:
                        document.status = '退件'
                        document.current_handler_id = None

                    db.session.commit()
                    print("數據庫更新成功")
                    
                    return jsonify({
                        'status': 'success',
                        'message': '處理成功'
                    })
                    
                except Exception as e:
                    db.session.rollback()
                    print(f"數據庫更新錯誤: {str(e)}")
                    return jsonify({
                        'status': 'error',
                        'message': f'數據更新失敗: {str(e)}'
                    }), 500

            except Exception as e:
                db.session.rollback()
                print(f"簽核處理錯誤: {str(e)}")
                return jsonify({
                    'status': 'error',
                    'message': f'簽核處理失敗: {str(e)}'
                }), 500
     
        # GET 請求處理
        previous_signatures = Forward.query.filter_by(
            document_id=doc_id,
            status='已簽核'
        ).order_by(Forward.order).all()

        return render_template('PDFsign.html',
                            document=document,
                            encryption_log=encryption_log,  # 確保這個變數被傳遞
                            decrypted_content=decrypted_content,
                            previous_signatures=previous_signatures,
                            user=user)
    
    except Exception as e:
        print(f"路由處理錯誤: {str(e)}")
        flash('處理請求時發生錯誤')
        return redirect(url_for('main.index'))
    
@main.route('/Setting-profile', methods=['GET', 'POST'])
@login_required
def profile():
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    message = None  # 添加訊息變數
    
    if request.method == 'POST':
        try:
            # 獲取表單數據
            department = request.form.get('department')
            phone = request.form.get('phone')
            extension = request.form.get('extension')
            
            # 更新用戶資料
            user.department = department
            user.phone = phone
            user.extension = extension
            
            db.session.commit()
            message = '個人資料更新成功！'  # 設置成功訊息
            
        except Exception as e:
            db.session.rollback()
            message = f'更新資料時發生錯誤：{str(e)}'  # 設置錯誤訊息
            
    return render_template('Setting-profile.html', user=user, message=message)

@main.route('/signature', methods=['GET'])
@login_required  # 確保用戶已登入
def signature():
    return render_template('PDF-signature.html')

@main.before_request
def check_session():
    # 不需要登入驗證的路由列表
    public_endpoints = ['main.login', 'main.logout', 'main.forgot_password', 'static']
    
    if (request.endpoint and 
        not request.endpoint.startswith('static.') and 
        request.endpoint not in public_endpoints and 
        'user_id' not in session):
        flash("請先登入。")
        return redirect(url_for('main.login'))

@main.context_processor
def inject_user():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        return dict(user=user)
    return dict(user=None)

@main.context_processor
def utility_processor():
    return dict(get_department_display_name=get_department_display_name)# ... existing code ...
@main.route('/preview_pdf/<int:doc_id>')
@login_required
def preview_pdf(doc_id):
    document = Document.query.get_or_404(doc_id)
    
    # 構建PDF文件的完整路徑
    file_path = os.path.join(current_app.root_path, 'static', 'upload', 'documents', document.file_path)
    
    try:
        return send_file(
            file_path,
            mimetype='application/pdf',  # 設為 'application/pdf' 表示在瀏覽器中預覽
            download_name=document.file_path
        )
    except Exception as e:
        flash(f'無法預覽文件：{str(e)}')
        return redirect(url_for('main.index'))

@main.route('/api/search', methods=['POST'])
@login_required
def search_documents():
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        print("接收到的搜尋條件:", data)
        
        # 分別查詢三種類型的文件
        # 1. 待處理的文件
        pending_query = Document.query.filter_by(
            current_handler_id=user_id,
            status='待簽核'
        )
        
        # 2. 已處理的文件
        processed_query = db.session.query(Document)\
            .join(Forward)\
            .filter(
                Forward.user_id == user_id,
                Forward.status.in_(['已簽核', '退件'])
            )
        
        # 3. 自己創建的文件
        created_query = Document.query.filter_by(
            creator_id=user_id
        )
        
        # 根據搜尋條件過濾
        if data.get('document_number'):
            pending_query = pending_query.filter(Document.number.like(f"%{data['document_number']}%"))
            processed_query = processed_query.filter(Document.number.like(f"%{data['document_number']}%"))
            created_query = created_query.filter(Document.number.like(f"%{data['document_number']}%"))
            
        if data.get('subject'):
            pending_query = pending_query.filter(Document.subject.like(f"%{data['subject']}%"))
            processed_query = processed_query.filter(Document.subject.like(f"%{data['subject']}%"))
            created_query = created_query.filter(Document.subject.like(f"%{data['subject']}%"))
            
        # 日期區間搜尋（只有當兩個日期都有填寫時才執行）
        if data.get('startDate') and data.get('endDate'):
            start_date = datetime.strptime(data['startDate'], '%Y-%m-%d')
            start_date = start_date.replace(hour=0, minute=0, second=0)
            end_date = datetime.strptime(data['endDate'], '%Y-%m-%d')
            end_date = end_date.replace(hour=23, minute=59, second=59)

             # 使用 OR 條件來搜尋創建日期或截止日期
            date_condition = db.or_(
                Document.created_at.between(start_date, end_date),
                Document.deadline.between(start_date, end_date)
            )
            
            pending_query = pending_query.filter(date_condition)
            processed_query = processed_query.filter(date_condition)
            created_query = created_query.filter(date_condition)
        
         
        # 合併查詢結果
        all_documents = pending_query.all() + processed_query.all() + created_query.all()
        
        # 去重
        documents = list(set(all_documents))
        # 按創建時間排序
        documents.sort(key=lambda x: x.created_at, reverse=True)
        
        print(f"找到 {len(documents)} 筆文件")
        
        # 格式化結果
        results = []
        for doc in documents:
            forward = Forward.query.filter_by(
                document_id=doc.id,
                user_id=user_id
            ).first()
            
            results.append({
                'priority': doc.urgency,
                'type': doc.type,
                'document_number': doc.number,
                'subject': doc.subject,
                'created_at': doc.created_at.strftime('%Y-%m-%d'),
                'signature_date': forward.signature_date.strftime('%Y-%m-%d') if forward and forward.signature_date else None,
                 'deadline': doc.deadline.strftime('%Y-%m-%d') if doc.deadline else None,  # 添加截止日期
                'recipient': User.query.get(doc.current_handler_id).username if doc.current_handler_id else '已結案',
                'status': forward.status if forward else doc.status
            })
        
        return jsonify(results)
        
    except Exception as e:
        print(f"搜尋錯誤: {str(e)}")
        return jsonify({'error': str(e)}), 400
    
    # ... existing code ...

@main.route('/view_document/<int:doc_id>')
@login_required
def view_document(doc_id):
    # 獲取文件資訊
    document = Document.query.get_or_404(doc_id)
    user_id = session.get('user_id')
    
    # 檢查權限 (只有文件的創建者、當前處理人或曾經處理過的人可以查看)
    if not (document.creator_id == user_id or 
            document.current_handler_id == user_id or 
            Forward.query.filter_by(document_id=doc_id, user_id=user_id).first()):
        flash('您沒有權限查看此文件')
        return redirect(url_for('main.index'))
    
    # 獲取附件列表
    attachments = Attachment.query.filter_by(document_id=doc_id).all()
    
    return render_template('View documents.html',
                         document=document,
                         attachments=attachments)

@main.route('/finish_document/<int:doc_id>')
@login_required
def finish_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    user_id = session.get('user_id')
    user = User.query.get(user_id)
    
    # 檢查權限
    is_creator = document.creator_id == user_id
    is_approver = Forward.query.filter_by(
        document_id=doc_id,
        user_id=user_id,
        is_approver=True
    ).first() is not None
    
    # 獲取創建者資訊
    creator = User.query.get(document.creator_id)
    
    # 如果是創文者或決行者，顯示所有簽核意見
    if is_creator or is_approver:
        signatures = Forward.query.filter(
            Forward.document_id == doc_id,
            Forward.signature_message.isnot(None)
        ).order_by(Forward.order).all()
    else:
        # 否則只顯示自己的簽核意見
        signatures = Forward.query.filter(
            Forward.document_id == doc_id,
            Forward.user_id == user_id,
            Forward.signature_message.isnot(None)
        ).order_by(Forward.order).all()
    
    # 獲取附件列表
    attachments = Attachment.query.filter_by(document_id=doc_id).all()
    
    return render_template('finish documents.html',
                         document=document,
                         signatures=signatures,
                         attachments=attachments,
                         user=user,
                         creator=creator,  # 添加創建者資訊
                         can_view_all_signatures=is_creator or is_approver)

@main.route('/download_attachment/<int:attachment_id>')
@login_required
def download_attachment(attachment_id):
    attachment = Attachment.query.get_or_404(attachment_id)
    document = Document.query.get(attachment.document_id)
    user_id = session.get('user_id')
    
    # 檢查權限
    if not (document.creator_id == user_id or 
            document.current_handler_id == user_id or 
            Forward.query.filter_by(document_id=document.id, user_id=user_id).first()):
        flash('您沒有權限下載此附件')
        return redirect(url_for('main.index'))
    
    file_path = os.path.join(current_app.root_path, 'static', 'upload', attachment.file_path)
    
    try:
        return send_file(
            file_path,
            download_name=attachment.filename,
            as_attachment=True
        )
    except Exception as e:
        flash(f'無法下載附件：{str(e)}')
        return redirect(url_for('main.view_document', doc_id=document.id))
    
@main.route('/download_document/<int:doc_id>')
@login_required
def download_document(doc_id):
    document = Document.query.get_or_404(doc_id)
    user_id = session.get('user_id')
    
    # 檢查權限
    if not (document.creator_id == user_id or 
            document.current_handler_id == user_id or 
            Forward.query.filter_by(document_id=doc_id, user_id=user_id).first()):
        flash('您沒有權限下載此文件')
        return redirect(url_for('main.index'))
    
    file_path = os.path.join(current_app.root_path, 'static', 'upload', 'documents', document.file_path)
    
    try:
        return send_file(
            file_path,
            download_name=document.file_path,
            as_attachment=True
        )
    except Exception as e:
        flash(f'下載文件時發生錯誤：{str(e)}')
        return redirect(url_for('main.finish_document', doc_id=doc_id))
    
@main.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        'status': 'error',
        'message': '上傳的檔案太大，請確保單個檔案不超過 16MB，總大小不超過 48MB'
    }), 413



















