from psycopg2 import IntegrityError
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, create_refresh_token, get_jwt
from datetime import datetime, timedelta
import os
import bcrypt
import binascii
import re
from sqlalchemy import func, or_
from sqlalchemy.orm import joinedload
from postmarker.core import PostmarkClient
from sqlalchemy.orm import joinedload
from werkzeug.utils import secure_filename
from flask_migrate import Migrate
import time
import threading
import psycopg2

app = Flask(__name__)
CORS(app)

version = "1.0.0-b3"


postmark = PostmarkClient(server_token='be4d882e-05e0-4ec5-8b79-188d034f678b', account_token='9a32a58c-d43a-4d24-92ba-9f26aad3f179', verbosity=3)

script_path = os.path.dirname(os.path.realpath(__file__))
raw_documents_file_path = os.path.join(script_path, "documents")
allowd_document_extensions = ['pdf', 'docx']

process_running = False

# app.config['SQLALCHEMY_DATABASE_URI'] = f'mysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_database}'
# app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:password@127.0.0.1:5432/postgres'

app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://db_7mm9_user:q4xtjVvpuUp18M7s4rAm6TEbvQah4NKI@dpg-cp0ir5o21fec7385mn2g-a.frankfurt-postgres.render.com:5432/db_7mm9'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'eyJSb2xlIjoiQWRtaW4iLCJJc3N1ZXIiOiJJc3N1ZXIiLeJVc2VybmFtZSI6IkphdmFiblVzZSIsImV4cCI6MTcxNTU0O1A4MCwiaWF0IjoxNzE1NTQ4MDgwfQ.FoLK5mWsOVR5CzVVanvr2QdtnNLUnZjMHn0SsFIXW08')
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=4)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=15)

db = SQLAlchemy(app)
jwt = JWTManager(app)

# migrate = Migrate(app, db)


class pro_users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    profile_picture = db.Column(db.String(40))
    password = db.Column(db.String(255), nullable=False)
    salt = db.Column(db.String(255), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    deleted = db.Column(db.Boolean, default=False)
    admin = db.Column(db.Boolean, default=False)
    departement = db.Column(db.Integer, db.ForeignKey('pro_departement_type.id'), nullable=True)

class pro_users_pending(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    admin = db.Column(db.Boolean, default=False)
    register_token = db.Column(db.String(80), nullable=False)


class pro_projects(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)
    project_file = db.Column(db.String(80), nullable=True)
    project_manager = db.Column(db.Integer, db.ForeignKey('pro_users.id'), nullable=True, default=None)
    locked = db.Column(db.Boolean, default=False, nullable=False)

class pro_projects_ressources(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    skill_id = db.Column(db.Integer, db.ForeignKey('pro_skills_type.id'), nullable=False)
    project_id = db.Column(db.Integer, db.ForeignKey('pro_projects.id'), nullable=False)
    time = db.Column(db.Integer, nullable=False)

class pro_ressources_connections(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_ressource_id = db.Column(db.Integer, db.ForeignKey('pro_projects_ressources.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('pro_users.id'), nullable=False)
    time = db.Column(db.Integer, nullable=False)

class pro_skills_type(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)

class pro_skills(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('pro_users.id'), nullable=False)
    skill_id = db.Column(db.Integer, db.ForeignKey('pro_skills_type.id'), nullable=False)
    level = db.Column(db.Integer, default=100)

class  pro_departement_type(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)

class  pro_contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('pro_users.id'), nullable=False)
    message = db.Column(db.String(255), nullable=False)

class pro_company(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=True)
    business_hours = db.Column(db.Integer, nullable=True)
    wiggle_room = db.Column(db.Integer, nullable=True)

class pro_company_closure(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=True)
    date = db.Column(db.String(20), nullable=True)
    type = db.Column(db.Integer, nullable=True)





def checkPasswordStrenght(password):
    if len(password) < 8 or not any(char.islower() for char in password) or not any(char.isupper() for char in password) or not re.compile(r'[!@#$%^&*(),.?":{}|<>]').search(password):
        return False
    return True



@jwt.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return jsonify(code="99", message="Token expired"), 200

@app.errorhandler(Exception)
def generic_error(error):
    print(error)
    return jsonify({"message": "An unexpected error occurred"}), 400


@app.errorhandler(404)
def page_not_found(error):
   return jsonify(code=100, message="Site not found"), 404


@app.route('/api/ping')
def ping():
    return jsonify({"message": "pong"}), 200

@app.route('/api/version')
def version_route():
    return jsonify({"version": version}), 200

@app.route('/api/authping')
@jwt_required()
def auth_ping():
    current_user = get_jwt_identity()
    return jsonify(code='0', message='pong', user=current_user), 200

@app.route('/api/user/refresh', methods=['GET'])
@jwt_required(refresh=True)
def refresh_token():
    current_user = get_jwt_identity()
    new_access_token = create_access_token(identity=current_user)
    return jsonify(code="0", access_token=new_access_token), 200


@app.route('/api/contact', methods=['POST'])
@jwt_required()
def contact():
    data = request.get_json()
    current_user = get_jwt_identity()
    subject = data.get('subject')
    message = data.get('message')

    user = pro_users.query.get(current_user)
    if not user:
        return jsonify(code='10', message="Invalid user"), 200

    if not subject:
        return jsonify(code='30', message='Please provide a subject'), 200
    
    if not message:
        return jsonify(code='40', message='Please provide a message'), 200
    else:
        if len(str(message)) > 250:
            return jsonify(code='50', message='Message to long'), 200

    new_message = pro_contact(
        user_id=current_user,
        subject=subject,
        message=message
    )

    try:
        db.session.add(new_message)
        db.session.commit()
        return jsonify(code="0", message='Message sent successfully'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error registering user: {str(e)}'), 500
    



@app.route('/api/user/preregister', methods=['POST'])
@jwt_required()
def pre_register():
    data = request.get_json()
    email = data.get('email')
    admin = data.get('admin')
    activation_token = binascii.hexlify(os.urandom(20)).decode()


    if not email:
        return jsonify(code='10', message='Please provide an email'), 200
    
    if pro_users.query.filter_by(email=email).first() or pro_users_pending.query.filter_by(email=email).first():
        return jsonify(code='20', message='Email already in use'), 200
    
    if not admin:
        admin = False
    else:
        admin = True


    
    new_user = pro_users_pending(
        email=email,
        admin=admin,
        register_token=activation_token
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        postmark.emails.send_with_template(
            TemplateId=35341396,
            TemplateModel={
                'action_url': 'https://properma.elias.uno/register?email='+email+'&token='+activation_token},
            From='properma@elias.uno',
            To=email,
        )
        # tbd send email to register
        return jsonify(code="0", message='User preregistered successfully'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error registering user: {str(e)}'), 500


@app.route('/api/user/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    first_name = data.get('first_name')
    last_name = data.get('last_name')
    password = data.get('password')
    register_token = data.get('token')

    if not email or not password or not first_name or not last_name or not register_token:
        return jsonify(code='30', message='First name, Last name, Email, the password and a token are required'), 200
    
    # if not departement or not pro_departement_type.query.filter_by(id=departement).first():
    #     departement = None
            
    if not checkPasswordStrenght(password):
        return jsonify(code='40', message='Password to weak'), 200
        

    preregistered_user = pro_users_pending.query.filter_by(email=email, register_token=register_token).first()
    if not preregistered_user:
        return jsonify(code='50', message='Invalid email or token'), 200
    
    email = preregistered_user.email
    admin = preregistered_user.admin
    
    encoded_password = password.encode('utf-8')

    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(encoded_password, salt)
    salt = str(salt, encoding='utf-8')
    hashed_password = str(hashed_password, encoding='utf-8')


    new_user = pro_users(
        email=email,
        first_name=first_name,
        last_name=last_name,
        admin=admin,
        password=hashed_password,
        salt=salt,
        profile_picture=None
    )

    try:
        with db.session.begin_nested():
            db.session.add(new_user)
            db.session.delete(preregistered_user)
            db.session.commit()
            return jsonify(code="0", message='User registered successfully'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error registering user: {str(e)}'), 500



@app.route('/api/user/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = pro_users.query.filter_by(email=email).first()
    
    if user:
        hashed_password = user.password

        if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
                if (user.enabled == True):
                    if (user.deleted == False):
                        access_token = create_access_token(identity=user.id)
                        refresh_token = create_refresh_token(identity=user.id)
                        return jsonify(code='0', access_token=access_token, user=user.id, refresh_token=refresh_token, message="Login successful")
                        # return jsonify(code='0', access_token=access_token, user=user.id, message="Login successful")
                    else:
                        return jsonify(code='40', message='Account deleted'), 200
                else:
                    return jsonify(code='10', message='Account disabled'), 200
        else:
            return jsonify(code='30', message='Invalid credentials'), 200
    else:
        return jsonify(code='30', message='Invalid credentials'), 200
    

@app.route("/api/user", methods=["GET"])
@jwt_required()
def get_users():
    try:
        # all_users = pro_users.query.all()

        
        try:
            user_id = int(request.args.get('id'))
            not_deleted_users = pro_users.query.filter_by(deleted=False, id=user_id).all()
        except:
            not_deleted_users = pro_users.query.filter_by(deleted=False).all()



        users_data = []
        for user in not_deleted_users:
            user_info = {
                'id': user.id,
                'email': user.email,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'profile_picture': user.profile_picture,
                'admin': user.admin,
                'enabled': user.enabled,
                'deleted': user.deleted,
                'departement': user.departement
            }
            users_data.append(user_info)
        return jsonify(code='0', message='User request successful', users= users_data), 200
    except Exception as e:
        return jsonify(message=f'Error retrieving users: {str(e)}'), 500

@app.route("/api/user/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_user(user_id):
    current_user = get_jwt_identity()
    try:
        user = pro_users.query.get(user_id)

        if not user:
            return jsonify(code='10', message='User not found'), 200

        pro_ressources_connections.query.filter_by(user_id=user.id).delete()
        pro_skills.query.filter_by(user_id=user.id).delete()
        pro_contact.query.filter_by(user_id=user.id).delete()

        # Delete the user
        db.session.delete(user)
        db.session.commit()

        return jsonify(code='0', message='User and associated data deleted successfully'), 200
    except Exception as e:
        db.session.rollback()
        return jsonify(code='20', message=f'Error deleting user: {str(e)}'), 200
    

@app.route('/api/user', methods=['PUT'])
@jwt_required()
def update_account():
    current_user = get_jwt_identity()
    data = request.get_json()
    new_first_name = data.get('first_name')
    new_last_name = data.get('last_name')
    # new_email = data.get('email')
 
 
    try:
        user = pro_users.query.get(current_user)
        if user:
            if new_first_name:
                user.first_name = new_first_name
 
            if new_last_name:
                user.last_name = new_last_name
  
            # if new_email:
            #     if pro_users.query.filter(pro_users.id != current_user, pro_users.email == new_email).first():
            #         return jsonify(code='20',message='There is already an account with this Email-Address'), 200
            #     if user.email != new_email:
            #         user.pending_email = new_email
            #         user.activation_token = binascii.hexlify(os.urandom(20)).decode()

            db.session.commit()
            #tbd send mail with token
 
            return jsonify(code='0', message='Account updated successfully'), 200
        else:
            return jsonify(code='30', message='There was an error while updating the account'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error updating account: {str(e)}'), 500

@app.route('/api/user/password', methods=['PUT'])
@jwt_required()
def password_change():
    current_user = get_jwt_identity()
    data = request.get_json()
    currentPassword = data.get('currentPassword')
    newPassword = data.get('newPassword')
    

    try:
        user = pro_users.query.get(current_user)
        if user:
            if currentPassword:
                if newPassword:
                    if not checkPasswordStrenght(newPassword):
                        return jsonify(code='40', message='Password to weak'), 200
                    
                    hashed_password = user.password
                    if bcrypt.checkpw(currentPassword.encode('utf-8'), hashed_password.encode('utf-8')):
                        new_hashed_password = bcrypt.hashpw(newPassword.encode('utf-8'), user.salt.encode('utf-8'))

                        user.password = str(new_hashed_password, encoding="utf-8")
                        db.session.commit()
                        return jsonify(code='0', message='Password updated successfully'), 200
                    else:
                        return jsonify(code='50', message='Invalid credentials'), 200

                else:
                    return jsonify(code='40', message='Please provide the new password'), 200
            else:
                return jsonify(code='30', message='Please provide the current password'), 200
        else:
            return jsonify(code='20', message='There was an error while updating the account'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error updating account: {str(e)}'), 500

    
@app.route("/api/user/pending", methods=["GET"])
@jwt_required()
def get_pending_users():
    try:
        all_users = pro_users_pending.query.all()



        users_data = []
        for user in all_users:
            user_info = {
                'id': user.id,
                'email': user.email,
                'admin': user.admin,
            }
            users_data.append(user_info)
        return jsonify(code='0', message='User request successful', users= users_data), 200
    except Exception as e:
        return jsonify(message=f'Error retrieving users: {str(e)}'), 500
    
@app.route("/api/user/pending/<int:user_id>", methods=["DELETE"])
@jwt_required()
def delete_pending_user(user_id):
    current_user = get_jwt_identity()
    try:
        user = pro_users_pending.query.get(user_id)

        if not user:
            return jsonify(code='10', message='User not found'), 200


        # Delete the user
        db.session.delete(user)
        db.session.commit()

        return jsonify(code='0', message='Pending user removed successfully'), 200
    except Exception as e:
        db.session.rollback()
        return jsonify(code='20', message=f'Error deleting pending user: {str(e)}'), 200    

@app.route("/api/company", methods=["GET"])
@jwt_required()
def get_company_details():
    try:
        
        companies = pro_company.query.all()

        companies_data = []
        for company_info in companies:
            company = {
                'id': company_info.id,
                'name': company_info.name,
                'business_hours': company_info.business_hours,
                'wiggle_room': company_info.wiggle_room,
            }
            companies_data.append(company)
        return jsonify(code='0', message='User request successful', company=companies_data), 200
    except Exception as e:
        return jsonify(message=f'Error retrieving users: {str(e)}'), 500


@app.route('/api/company', methods=['PUT'])
@jwt_required()
def update_company_information():
    data = request.get_json()
    business_hours = data.get('business_hours')
    wiggle_room = data.get('wiggle_room')
    name = data.get('name')

    try:
        company = pro_company.query.first()
        if company:
            if business_hours or business_hours == "":
                company.business_hours = business_hours or None

            if wiggle_room or wiggle_room == "":
                company.wiggle_room = wiggle_room or None

            if name or name == "":
                company.name = name or None

            db.session.commit()

            return jsonify(code='0', message='Information updated successfully'), 200
        else:
            return jsonify(code='10', message='Company not found'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error updating account: {str(e)}'), 500
    
@app.route('/api/company/closure', methods=['GET'])
@jwt_required()
def get_company_closure():
    try:
        closures = pro_company_closure.query.all()

        closures_data = []
        for closure_row in closures:
            closure = {
                'id': closure_row.id,
                'name': closure_row.name,
                'type': closure_row.type,
                'date': closure_row.date,
            }
            closures_data.append(closure)

        return jsonify(code='0', message='Request successful', closures=closures_data), 200
    except Exception as e:
        return jsonify(message=f'Error retrieving users: {str(e)}'), 500


@app.route('/api/company/closure', methods=['POST'])
@jwt_required()
def update_company_closure():
    data = request.get_json()
    name = data.get('name')
    type = data.get('type')
    date_str = data.get('date')

    try:
        if type is None and date_str is None:
            return jsonify(code='40', message='Either type or date should be provided'), 200

        if type is not None and date_str is not None:
            return jsonify(code='20', message='Either type or date should be provided, not both'), 200

        if type is not None and (int(type) < 0 or int(type) > 8):
            return jsonify(code='30', message='Type should be between 0 and 8'), 200

        if type is not None:
            existing_closure = pro_company_closure.query.filter_by(type=type).first()
            if existing_closure:
                return jsonify(code='50', message='A closure with the same type already exists'), 200
            new_closure = pro_company_closure(type=type)
        elif date_str is not None:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
            existing_closure = pro_company_closure.query.filter_by(date=date).first()
            if existing_closure:
                return jsonify(code='60', message='A closure with the same date already exists'), 200
            new_closure = pro_company_closure(date=date)

        if name:
            new_closure.name = name

        db.session.add(new_closure)
        db.session.commit()

        return jsonify(code='0', message='Successfully added the closure'), 200
        
    except Exception as e:
        print(e)
        return jsonify(code='10', message='Error occurred: {}'.format(str(e))), 200
    

@app.route('/api/company/closure/<int:closure_id>', methods=['DELETE'])
@jwt_required()
def delete_company_closure(closure_id):
    try:
        closure = pro_company_closure.query.get(closure_id)
        if closure:
            db.session.delete(closure)
            db.session.commit()
            return jsonify(code='0', message='Closure deleted successfully'), 200
        else:
            return jsonify(code='10', message='Closure not found'), 200
    except Exception as e:
        return jsonify(code='500', message=f'Error occurred: {str(e)}'), 500



@app.route("/api/project", methods=["GET"])
@jwt_required()
def get_projects():
    try:
        all_projects = pro_projects.query.all()

        projects_data = []
        for project in all_projects:
            project_info = {
                'id': project.id,
                'name': project.name,
                'description': project.description,
                'project_file': project.project_file,
                'manager:': project.project_manager,
                'lock': project.locked
            }
            projects_data.append(project_info)
        return jsonify(code='0', message='Project request successful', projects= projects_data), 200
    except Exception as e:
        return jsonify(message=f'Error retrieving projects: {str(e)}'), 500

@app.route("/api/project", methods=["POST"])
@jwt_required()
def create_projects():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')


    if not name:
        return jsonify(code='10', message='Please provide a name'), 200
    
    if pro_projects.query.filter_by(name=name).first():
        return jsonify(code='30', message="There is already a project with the name '"+name+"'"), 200

    if description:
        if len(description) > 250:
            return jsonify(code='20', message='Description too long'), 200


    # os.makedirs(raw_documents_file_path, exist_ok=True)

    # if file:
    #     filename, file_extension = os.path.splitext(file.filename)
    #     file_extension = file_extension.lower()[1:]
    #     if file_extension not in allowd_document_extensions:
    #         return jsonify(code='40', message='File extension not allowed')
    #     while True:
    #         filename = secrets.token_hex(16) + '.' + file_extension
    #         file_path = os.path.join(raw_documents_file_path, filename)
    #         if not os.path.exists(file_path):
    #             file.save(file_path)
    #             break
    # else:
    #     filename = None

    new_project = pro_projects(
        name=str(name),
        description=str(description)
    )

    try:
        db.session.add(new_project)
        db.session.commit()
        return jsonify(code=0, message='Project created successfully'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error creating project: {str(e)}'), 500
    

@app.route("/api/project/<int:project_id>", methods=["DELETE"])
@jwt_required()
def delete_project(project_id):
    current_user = get_jwt_identity()

    try:
        project = pro_projects.query.get(project_id)

        if not project:
            return jsonify(code='10', message='Project not found'), 200


        # Delete project resources
        pro_projects_ressources.query.filter_by(project_id=project.id).delete()

        # Delete resource connections related to the project
        pro_ressources_connections.query.filter(pro_ressources_connections.project_ressource_id.in_(db.session.query(pro_projects_ressources.id).filter_by(project_id=project.id))).delete(synchronize_session='fetch')

        # Delete the project
        db.session.delete(project)
        db.session.commit()

        return jsonify(code='0', message='Project and associated data deleted successfully'), 200
    except Exception as e:
        db.session.rollback()
        print(e)
        return jsonify(code='20', message=f'Error deleting project: {str(e)}'), 200

@app.route('/api/project/<int:project_id>', methods=['PUT'])
@jwt_required()
def update_project(project_id):
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    lock = data.get('lock')

    try:
        project = pro_projects.query.filter_by(id=project_id).first()
        if project:
            if name or name == "":
                project.name = name or None

            if description or description == "":
                project.description = description or None

            if lock is not None:
                if lock:
                    project.locked = True
                if not lock:
                    project.locked = False

            db.session.commit()

            return jsonify(code='0', message='Project updated successfully'), 200
        else:
            return jsonify(code='10', message='Project not found'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error updating account: {str(e)}'), 500




@app.route("/api/skills", methods=["GET"])
@jwt_required()
def get_skill_types():
    try:
        all_skills = pro_skills_type.query.all()

        skills_data = []
        for skill in all_skills:
            skill_info = {
                'id': skill.id,
                'name': skill.name,
                'description': skill.description
            }
            skills_data.append(skill_info)
        return jsonify(code='0', message='Skill types request successful', skills= skills_data), 200
    except Exception as e:
        return jsonify(message=f'Error retrieving projects: {str(e)}'), 500

@app.route("/api/skills", methods=["POST"])
@jwt_required()
def create_skill_type():
    data = request.get_json()
    name = data.get('name')
    description = data.get('description')


    if not name:
        return jsonify(code='10', message='Please provide a name'), 200
    
    if pro_skills_type.query.filter_by(name=name).first():
        return jsonify(code='30', message="There is already a skilltype with the name '"+name+"'"), 200

    if description:
        if len(description) > 250:
            return jsonify(code='20', message='Description too long'), 200

    new_skill_type = pro_skills_type(
        name=str(name),
        description=str(description)
    )

    try:
        db.session.add(new_skill_type)
        db.session.commit()
        return jsonify(code=0, message='Skill Type created successfully'), 200
    except IntegrityError as e:
        db.session.rollback()
        return jsonify(message=f'Error creating Skill Type: {str(e)}'), 500
    

@app.route("/api/skills/<int:skill_id>", methods=["DELETE"])
@jwt_required()
def delete_skill_type(skill_id):
    current_user = get_jwt_identity()

    try:
        skill = pro_skills_type.query.get(skill_id)

        if not skill:
            return jsonify(code='10', message='Skill Type not found'), 200


        pro_skills.query.filter_by(skill_id=skill.id).delete()
        pro_projects_ressources.query.filter_by(skill_id=skill.id).delete()

        db.session.delete(skill)
        db.session.commit()

        return jsonify(code='0', message='Skill Type and associated data deleted successfully'), 200
    except Exception as e:
        db.session.rollback()
        return jsonify(code='20', message=f'Error deleting skill type: {str(e)}'), 200



#=========================================================================================


@app.route("/api/user/<int:user_id>/skills", methods=["GET"])
@jwt_required()
def get_user_skills(user_id):
    # current_user = get_jwt_identity()
    try:
        user = pro_users.query.get(user_id)

        if not user:
            return jsonify(code='10', message='User not found'), 200
        
        # user_skills = pro_skills.query.filter_by(user_id=user_id).all()
        user_skills = db.session.query(pro_skills, pro_skills_type).filter(pro_skills.user_id == user.id).join(pro_skills_type).all()


        skills_list = []
        for skill, skill_type in user_skills:
            skill_info = {
                'id': skill.id,
                'skill_type_id': skill_type.id,
                'name': skill_type.name,
                'description': skill_type.description,
                'level': skill.level
            }
            skills_list.append(skill_info)

        return jsonify(code='0', message='Success', skills=skills_list), 200
        
    except Exception as e:
        return jsonify(code='20', message='Error occurred: {}'.format(str(e))), 200
    

@app.route("/api/user/<int:user_id>/skills", methods=["POST"])
@jwt_required()
def add_user_skills(user_id):
    # current_user = get_jwt_identity()
    try:
        user = pro_users.query.get(user_id)

        if not user:
            return jsonify(code='10', message='User not found'), 200


        # tbd check if not exists already
        data = request.get_json()
        skill_id = data.get('skill_id')
        level = data.get('level')


        if level and (not isinstance(level, int) or int(level) < 0 or int(level) > 200):
            return jsonify(code='50', message='Invalid level value. Level must be between 0 and 200'), 200
            
        if not level:
            level = 100

        existing_skill = pro_skills.query.filter_by(user_id=user_id, skill_id=skill_id).first()
        if existing_skill:
            return jsonify(code='70', message='Skill already exists for this user'), 200


        skill_type = pro_skills_type.query.get(skill_id)
        if not skill_type:
            return jsonify(code='30', message='Skill type not found'), 200

        new_skill = pro_skills(user_id=user_id, skill_id=skill_id, level=level)
        db.session.add(new_skill)
        db.session.commit()
        return jsonify(code='0', message='Skill added successfully'), 200
        
    
    except Exception as e:
        return jsonify(code='20', message='Error occurred: {}'.format(str(e))), 200


@app.route("/api/user/<int:user_id>/skills/<int:skill_id>", methods=["DELETE"])
@jwt_required()
def delete_user_skills(user_id, skill_id):
    # current_user = get_jwt_identity()
    try:
        user = pro_users.query.get(user_id)

        if not user:
            return jsonify(code='10', message='User not found'), 200
        

        skill = pro_skills.query.filter_by(user_id=user_id, skill_id=skill_id).first()
        if not skill:
            return jsonify(code='40', message='User does not have this skill'), 200

        db.session.delete(skill)
        db.session.commit()

        return jsonify(code='0', message='Skill removed successfully'), 200


    except Exception as e:
        return jsonify(code='20', message='Error occurred: {}'.format(str(e))), 200








@app.route("/api/project/ressources/<int:project_id>", methods=["GET"])
@jwt_required()
def get_project_ressources(project_id):
    current_user = get_jwt_identity()
    try:
        # user = pro_users.query.get(current_user)
        
        
        

        project_ressources = db.session.query(pro_projects_ressources, pro_skills_type, pro_projects).filter(pro_projects_ressources.project_id == project_id).join(pro_skills_type).join(pro_projects).all()


        ressources_list = []
        for project_ressource, skill_types, project in project_ressources:
            ressource = {
                'id': project_ressource.id,
                'skill_name': skill_types.name,
                'project_id': project_ressource.project_id,
                'project_name': project.name,
                'skill_id': project_ressource.skill_id,
                'time': project_ressource.time
            }
            ressources_list.append(ressource)
        


        return jsonify(code='0', message='Success', project_ressources=ressources_list), 200
        
    except Exception as e:
        return jsonify(code='10', message='Error occurred: {}'.format(str(e))), 200
    

@app.route("/api/project/ressources", methods=["POST"])
@jwt_required()
def create_project_ressources():
    current_user = get_jwt_identity()
    try:
        data = request.get_json()
        skill_id = data.get('skill_id')
        project_id = data.get('project_id')
        time = data.get('time')


        if time and (not isinstance(time, int) or int(time) < 0 or int(time) > 999999999):
            return jsonify(code='50', message='Invalid time value. Time must be between 0 and 999999999 (in seconds)'), 200
            

        skill_type = pro_skills_type.query.get(skill_id)
        if not skill_type:
            return jsonify(code='30', message='Skill type not found'), 200
        
        project = pro_projects.query.get(project_id)
        if not project:
            return jsonify(code='40', message='Project not found'), 200

        existing_ressource = pro_projects_ressources.query.filter_by(skill_id=skill_type.id, project_id=project.id).first()
        if existing_ressource:
            return jsonify(code='70', message='An entry with this skill for this project already exists'), 200


        new_project_ressource = pro_projects_ressources(project_id=project.id, skill_id=skill_type.id, time=time)
        db.session.add(new_project_ressource)
        db.session.commit()

        return jsonify(code='0', message='Successfully added the project ressource'), 200
        
    except Exception as e:
        return jsonify(code='10', message='Error occurred: {}'.format(str(e))), 200


@app.route("/api/project/ressources/<int:ressource_id>", methods=["DELETE"])
@jwt_required()
def delete_project_ressource(ressource_id):
    # current_user = get_jwt_identity()
    try:
        

        project_ressource = pro_projects_ressources.query.filter_by(id=ressource_id).first()
        if not project_ressource:
            return jsonify(code='40', message='Ressource does not exist'), 200

        db.session.delete(project_ressource)
        db.session.commit()

        return jsonify(code='0', message='Ressource deleted successfully'), 200


    except Exception as e:
        return jsonify(code='20', message='Error occurred: {}'.format(str(e))), 200


@app.route("/api/project/ressources/<int:ressource_id>", methods=["PUT"])
@jwt_required()
def update_project_ressource(ressource_id):
    try:
        data = request.get_json()
        new_time = data.get('time')

        if new_time is None or (not isinstance(new_time, int) or int(new_time) < 0 or int(new_time) > 999999999):
            return jsonify(code='40', message='Invalid time value. Time must be between 0 and 999999999 (in s)'), 200

        project_ressource = pro_projects_ressources.query.get(ressource_id)
        if not project_ressource:
            return jsonify(code='30', message='Resource does not exist'), 200

        project_ressource.time = new_time
        db.session.commit()

        return jsonify(code='0', message='Resource time updated successfully'), 200

    except Exception as e:
        return jsonify(code='10', message='Error occurred: {}'.format(str(e))), 200
    

@app.route("/api/project/ressources/connections/<int:project_id>/user/<int:user_id>", methods=["GET"])
@jwt_required()
def get_ressource_connection(project_id, user_id):
    current_user = get_jwt_identity()
    try:
        # user = pro_users.query.get(current_user)
        
        
        

        ressource_connections = db.session.query(pro_ressources_connections, pro_users).filter(pro_projects_ressources.project_id == project_id, pro_ressources_connections.user_id == user_id).join(pro_users).all()


        connections_list = []
        for ressource_connections, users in ressource_connections:
            ressource = {
                'id': ressource_connections.id,
                'project_ressource_id': ressource_connections.project_ressource_id,
                'user_id': ressource_connections.user_id,
                'user_name': users.first_name + ' ' + users.last_name,
                'time': ressource_connections.time
            }
            connections_list.append(ressource)
        


        return jsonify(code='0', message='Successfully fetched the ressource connections', data=connections_list), 200
        
    except Exception as e:
        return jsonify(code='10', message='Error occurred: {}'.format(str(e))), 200


@app.route("/api/project/ressources/connections", methods=["POST"])
@jwt_required()
def create_ressource_connection():
    current_user = get_jwt_identity()
    try:
        data = request.get_json()
        project_ressource_id = data.get('project_ressource_id')
        user_id = data.get('user_id')
        time = data.get('time')


        if time and (not isinstance(time, int) or int(time) < 0 or int(time) > 999999999):
            return jsonify(code='10', message='Invalid time value. Time must be between 0 and 999999999 (in seconds)'), 200
            

        # skill_type = pro_skills_type.query.get(skill_id)
        # if not skill_type:
        #     return jsonify(code='30', message='Skill type not found'), 200
        
        # project = pro_projects.query.get(project_id)
        # if not project:
        #     return jsonify(code='40', message='Project not found'), 200

        # existing_ressource = pro_projects_ressources.query.filter_by(skill_id=skill_type.id, project_id=project.id).first()
        # if existing_ressource:
        #     return jsonify(code='70', message='An entry with this skill for this project already exists'), 200


        # new_project_ressource = pro_projects_ressources(project_id=project.id, skill_id=skill_type.id, time=time)
        # db.session.add(new_project_ressource)
        # db.session.commit()

        return jsonify(code='0', message='Successfully added the project ressource'), 200
        
    except Exception as e:
        return jsonify(code='10', message='Error occurred: {}'.format(str(e))), 200


# @app.route("/api/process", methods=["POST"])
# @jwt_required()
# def start_process():
#     global process_running
#     current_user = get_jwt_identity()
#     try:
#         data = request.get_json()
#         wiggle_room = data.get('wiggle_room')
#         business_hours = data.get('business_hours')

#         process_running = True
#         time.sleep(30)







#         process_running = False

#         return jsonify(code='0', message='Successfully processed'), 200
        
#     except Exception as e:
#         process_running = False
#         return jsonify(code='10', message='Error occurred: {}'.format(str(e))), 200
    
# @app.route("/api/process/status", methods=["GET"])
# @jwt_required()
# def check_process_status():
#     global process_running
#     current_user = get_jwt_identity()
#     try:
#         if process_running == True:
#             return jsonify(code='1', message='The process is running right now'), 200
#         else:
#             return jsonify(code='0', message='Ready to run the process'), 200
#     except Exception as e:
#         return jsonify(code='10', message='Error occurred: {}'.format(str(e))), 200  


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False, host='0.0.0.0', port=5000)
