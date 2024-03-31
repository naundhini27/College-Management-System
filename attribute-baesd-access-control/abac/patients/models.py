from uuid import uuid4
from abac import bcrypt, mongo
from datetime import datetime
from flask import session
from abac.workers.models import Worker
import binascii, secrets
from tinyec import registry
import ecc

curve = registry.get_curve('brainpoolP256r1')
privKey = 29602356343871707410420205002392794180866553223632945850562014741270236846432
pubKey = privKey * curve.g

# the User class
class Patient:
    # initializing the class
    def __init__(self, name=None, email=None, password=None, address=None, number=None, gender=None):
        self.name = name
        self.email = email
        self.password = password
        self.address = address
        self.number = number
        self.gender = gender

    # signup helper function
    def signup(self):

        try:
            encryptedMsg_n = ecc.encrypt_ECC(self.name.title().strip().encode('ASCII'), pubKey)
            encryptedMsgObj_n = {
                'ciphertext': binascii.hexlify(encryptedMsg_n[0]).decode(),
                'nonce': binascii.hexlify(encryptedMsg_n[1]).decode(),
                'authTag': binascii.hexlify(encryptedMsg_n[2]).decode(),
                'ciphertextPubKey': hex(encryptedMsg_n[3].x) + hex(encryptedMsg_n[3].y % 2)[2:]
            }            
            encryptedMsg_e = ecc.encrypt_ECC(self.email.lower().encode('ASCII'), pubKey)
            encryptedMsgObj_e = {
                'ciphertext': binascii.hexlify(encryptedMsg_e[0]).decode(),
                'nonce': binascii.hexlify(encryptedMsg_e[1]).decode(),
                'authTag': binascii.hexlify(encryptedMsg_e[2]).decode(),
                'ciphertextPubKey': hex(encryptedMsg_e[3].x) + hex(encryptedMsg_e[3].y % 2)[2:]
            }
            encryptedMsg_num = ecc.encrypt_ECC(self.number.encode('ASCII'), pubKey)
            encryptedMsgObj_num = {
                'ciphertext': binascii.hexlify(encryptedMsg_num[0]).decode(),
                'nonce': binascii.hexlify(encryptedMsg_num[1]).decode(),
                'authTag': binascii.hexlify(encryptedMsg_num[2]).decode(),
                'ciphertextPubKey': hex(encryptedMsg_num[3].x) + hex(encryptedMsg_num[3].y % 2)[2:]
            }
            encryptedMsg_add = ecc.encrypt_ECC(self.address.encode('ASCII'), pubKey)
            encryptedMsgObj_add = {
                'ciphertext': binascii.hexlify(encryptedMsg_add[0]).decode(),
                'nonce': binascii.hexlify(encryptedMsg_add[1]).decode(),
                'authTag': binascii.hexlify(encryptedMsg_add[2]).decode(),
                'ciphertextPubKey': hex(encryptedMsg_add[3].x) + hex(encryptedMsg_add[3].y % 2)[2:]
            }
            encryptedMsg_g = ecc.encrypt_ECC(self.gender.encode('ASCII'), pubKey)
            encryptedMsgObj_g = {
                'ciphertext': binascii.hexlify(encryptedMsg_g[0]).decode(),
                'nonce': binascii.hexlify(encryptedMsg_g[1]).decode(),
                'authTag': binascii.hexlify(encryptedMsg_g[2]).decode(),
                'ciphertextPubKey': hex(encryptedMsg_g[3].x) + hex(encryptedMsg_g[3].y % 2)[2:]
            }
            user = {
                'id' : self.name.title().strip(),
                'public_id': uuid4().hex,
                'name': encryptedMsgObj_n,
                'email': encryptedMsgObj_e,
                'password': bcrypt.generate_password_hash(
                    self.password).decode('utf-8'),
                'number': encryptedMsgObj_num,
                'privkey':str(privKey),
                'address': encryptedMsgObj_add,
                'gender': encryptedMsgObj_g,
                'dateCreated': datetime.utcnow()
            }
            mongo.db.patients_.insert_one(user)
            '''
            user = {
                'public_id': uuid4().hex,
                'name': self.name.title().strip(),
                'email': self.email.lower(),
                'password': bcrypt.generate_password_hash(
                    self.password).decode('utf-8'),
                'number': self.number,
                'address': self.address,
                'gender': self.gender,
                'dateCreated': datetime.utcnow()
            }
            mongo.db.patients.insert_one(user)
            '''
            usr = {
                'public_id': uuid4().hex,
                'name': self.name.title().strip(),
                'email': self.email.lower(),
                'password': bcrypt.generate_password_hash(
                    self.password).decode('utf-8'),
                'number': self.number,
                'address': self.address,
                'gender': self.gender,
                'dateCreated': datetime.utcnow()
            }
            mongo.db.patients.insert_one(usr)
        except:
            return False

        return True

    # creating a user session
    @staticmethod
    def init_session(user):
        session['is_authenticated'] = True
        del user['password']
        del user['_id']
        session['current_user'] = user
        session.permanent = True
        return user

    # signin helper function
    def signin(self, signin_data):
        # querying user from db with username
        signin_data['identifier'].lower()
        user = mongo.db.patients.find_one(
            {"username": signin_data['identifier'].lower()})

        # validating user and password
        if user and bcrypt.check_password_hash(user["password"], signin_data['password']):
            return self.init_session(user)

        else:
            # querying user from db  with email
            user = mongo.db.patients.find_one(
                {"email": signin_data['identifier'].lower()})

            # validating user and password
            if user and bcrypt.check_password_hash(user["password"], signin_data['password']):
                return self.init_session(user)

        return False

    # signout helper function
    @staticmethod
    def signout():
        if session['is_authenticated'] and session['current_user']:
            session['is_authenticated'] = False
            del session['current_user']
        return True

    # email validator helper function
    @staticmethod
    def check_email(email):
        e = ecc.encrypt_ECC(email.encode('ASCII'),pubKey)
        mongo.db.patients_.find_one({"email.ciphertext" :binascii.hexlify(e[0]).decode()})
        return mongo.db.patients.find_one({"email" :email})

    # number validator helper function
    @staticmethod
    def check_number(number):
        num = ecc.encrypt_ECC(number.encode('ASCII'),pubKey)
        mongo.db.patients_.find_one({"number.ciphertext" : binascii.hexlify(num[0]).decode()})
        return mongo.db.patients.find_one({"number" :number})

    # user retrieval helper function
    @staticmethod
    def get_user(public_id):
        return mongo.db.patients.find_one({"public_id": public_id})

    # profile update helper function
    def update_profile(self, id, data):
        try:
            updateData = data
            user = self.get_user(id)

            # creating the update and commiting to the DB
            if len(updateData) > 0:
                update = {"$set": updateData}
                filterData = {'public_id': user['public_id']}
                mongo.db.patients.update_one(filterData, update)

            # getting the new data of the user
            userUpdate = self.get_user(id)
            # starting a new session for the user
            userData = self.init_session(userUpdate)

            response = {
                "status": True,
                "message": "Your profile has been updated successfully",
                "userData": userData
            }

        except:
            response = {
                "status": False,
                "error": "Something went wrong. Please try again."
            }
            # return response
        return response

    # get all patients
    @staticmethod
    def get_patients():
        return mongo.db.patients.find()

    # password update helper function
    def update_password(self, id, data):

        updateData = {}

        user = self.get_user(id)
        # checking the old password
        if not (bcrypt.check_password_hash(user['password'], data['cpass'])):
            raise ValueError

        # hashing the new password
        newPassword = bcrypt.generate_password_hash(
            data['npass']).decode("utf-8")

        # adding password to the db
        mongo.db.patients.update_one(
            {'public_id': id}, {'$set': {'password': newPassword}})

    # helper functions for getting patient records
    @staticmethod
    def get_mp(id):
        # medicine prescription
        return mongo.db.medicine.find_one({'patient': id})

    @staticmethod
    def get_vi(id):
        # patient vitals
        return mongo.db.vitals.find_one({'patient': id})

    @staticmethod
    def get_dt(id):
        # diagnostics tests
        return mongo.db.tests.find_one({'patient': id})

    @staticmethod
    def get_ph(id):
        # diagnostics tests
        return mongo.db.history.find_one({'patient': id})
    # helper functions for getting patient records end

    # helper function for saving patient records
    def save_mp(self, id, data):

        obj = {
            'patient': id,
            'record': data
        }
        obj2 = {

            'record': data
        }

        if self.get_mp(id):
            update = {"$set": obj2}
            filterData = {'patient': id}
            mongo.db.medicine.update_one(filterData, update)
        else:
            mongo.db.medicine.insert_one(obj)

        response = {
            "status": True,
            "message": "Record saved successfully",
        }

        return response

    def save_vi(self, id, data):

        obj = {
            'patient': id,
            'record': data
        }
        obj2 = {
            'record': data
        }

        if self.get_vi(id):

            update = {"$set": obj2}
            filterData = {'patient': id}
            mongo.db.vitals.update_one(filterData, update)
        else:
            mongo.db.vitals.insert_one(obj)

        response = {
            "status": True,
            "message": "Record saved successfully",
        }

        return response

    def save_dt(self, id, data):

        obj = {
            'patient': id,
            'record': data
        }
        obj2 = {
            'record': data
        }

        if self.get_dt(id):

            update = {"$set": obj2}
            filterData = {'patient': id}
            mongo.db.tests.update_one(filterData, update)
        else:
            mongo.db.tests.insert_one(obj)

        response = {
            "status": True,
            "message": "Record saved successfully",
        }

        return response

    def save_ph(self, id, data):

        obj = {
            'patient': id,
            'record': data
        }
        obj2 = {
            'record': data
        }

        if self.get_ph(id):

            update = {"$set": obj2}
            filterData = {'patient': id}
            mongo.db.history.update_one(filterData, update)
        else:
            mongo.db.history.insert_one(obj)

        response = {
            "status": True,
            "message": "Record saved successfully",
        }

        return response
    # helper function for saving patient records end

    # helper function for getting all messages
    @staticmethod
    def get_messages(id):
        return mongo.db.messages.find({'receiver': id}).sort('dateSent', -1)

    # helper function for getting all sent messages
    @staticmethod
    def sent_messages(id):
        return mongo.db.messages.find({'senderId': id}).sort('dateSent', -1)

    # helper function for getting all trashed messages
    @staticmethod
    def trashed_messages(id):
        return mongo.db.messages.find({'senderId': id, "hasDeleted": True}).sort('dateSent', -1)

    @staticmethod
    def get_unread(id):
        return mongo.db.messages.find({'receiver': id, 'hasRead': False}).sort('dateSent', -1)

    # helper function for requesting access to data
    @staticmethod
    def grantReadAccess(worker, user, record):

        # computing the message to send
        messages = {
            "mp": f"This is to inform you that patient {user['name']} has granted you access to view their Medical Prescription data. You can verify this using the button below",
            "vi": f"This is to inform you that patient {user['name']} has granted you access to view their Medical Health Vitals data. You can verify this using the button below",
            "dt": f"This is to inform you that patient {user['name']} has granted you access to view their Medical Recommended Diagnostics data. You can verify this using the button below",
            "ph": f"This is to inform you that patient {user['name']} has granted you access to view their Personal and Health History data. You can verify this using the button below",
        }
        # creating the message object
        new_message = {
            "receiver": worker['public_id'],
            "senderName": user['name'],
            "senderId": user['public_id'],
            "dateSent": datetime.utcnow(),
            "hasRead": False,
            "message": messages[record],
            "senderEmail": user['email'],
            "title": "Access Granted to View Requested Health Records",
            "senderRole": 'Patient',
            "messageType": "request",
            "hasDeleted": False,
            "recordType": record,
            "messageId": uuid4().hex
        }
        # adding the message to the database
        mongo.db.messages.insert(new_message)

    # helper function for sending message
    @staticmethod
    def sendMessage(form, user):

        # creating the message object
        new_message = {
            "receiver": form['receiver'],
            "senderName": user['name'],
            "senderId": user['public_id'],
            "dateSent": datetime.utcnow(),
            "hasRead": False,
            "message": form['message'],
            "senderEmail": user['email'],
            "title": form['title'],
            "senderRole": 'Patient',
            "messageType": "message",
            "hasDeleted": False,
            "messageId": uuid4().hex
        }
        # adding the message to the database
        mongo.db.messages.insert(new_message)

    # helper function for requesting access to data
    @staticmethod
    def grantWriteAccess(worker, user, record):

        # computing the message to send
        messages = {
            "mp": f"This is to inform you that patient {user['name']} has granted you access to view and edit their Medical Presciption data. You can verify this using the button below",
            "vi": f"This is to inform you that patient {user['name']} has granted you access to view and edit their Medical Health Vitals data. You can verify this using the button below",
            "dt": f"This is to inform you that patient {user['name']} has granted you access to view and edit their Medical Recommended Diagnostics data. You can verify this using the button below",
            "ph": f"This is to inform you that patient {user['name']} has granted you access to view and edit their Personal and Health History data. You can verify this using the button below",
        }
        # creating the message object
        new_message = {
            "receiver": worker['public_id'],
            "senderName": user['name'],
            "senderId": user['public_id'],
            "dateSent": datetime.utcnow(),
            "hasRead": False,
            "message": messages[record],
            "senderEmail": user['email'],
            "title": "Access Granted to View and Edit Requested Health Records",
            "senderRole": 'Patient',
            "messageType": "request",
            "hasDeleted": False,
            "recordType": record,
            "messageId": uuid4().hex
        }
        # adding the message to the database
        mongo.db.messages.insert(new_message)

    # helper function for requesting access to data
    @staticmethod
    def declineAccess(worker, user, record):

        # computing the message to send
        messages = {
            "mp": f"This is to inform you that patient {user['name']} has declined your request access their Medical Presciption data. You can trying sending the patient a message",
            "vi": f"This is to inform you that patient {user['name']} has declined your request access their Medical Health Vitals data. You can trying sending the patient a message",
            "dt": f"This is to inform you that patient {user['name']} has declined your request access their Medical Recommended Diagnostics data. You can trying sending the patient a message",
            "ph": f"This is to inform you that patient {user['name']} has declined your request access their Personal and Health History data. You can trying sending the patient a message",
        }
        # creating the message object
        new_message = {
            "receiver": worker['public_id'],
            "senderName": user['name'],
            "senderId": user['public_id'],
            "dateSent": datetime.utcnow(),
            "hasRead": False,
            "message": messages[record],
            "senderEmail": user['email'],
            "title": "Access Denied to View/Edit Requested Health Records",
            "senderRole": 'Patient',
            "messageType": "decline",
            "hasDeleted": False,
            "recordType": record,
            "messageId": uuid4().hex
        }
        # adding the message to the database
        mongo.db.messages.insert(new_message)

    # helper function to validate if data request has been sent already
    @staticmethod
    def checkRequest(pid, wid):
        return mongo.db.requests.find_one({'workerId': wid, 'patientId': pid})

    # deleting the request access sent
    @staticmethod
    def deleteRequest(patient, user, data):

        present = Patient.checkRequest(patient['public_id'], user['public_id'])

        if data in present['recordType']:
            present['recordType'].remove(data)
            mongo.db.requests.update_one({'_id': present['_id']}, {
                '$set': {'recordType': present['recordType']}})
        else:
            pass
        return True

    # helper function for updating messages
    @staticmethod
    def updateMessage(id, data):
        # adding the update to the db
        mongo.db.messages.update_one({'messageId': id}, {'$set': data})
        return True

    # helper function for booking appointments
    @staticmethod
    def book(form, user):
        worker = Worker.get_worker(form['worker'])
        # creating the appointment object
        booking = {
            "workerId": worker['public_id'],
            "workerName": f"{worker['fname']} {worker['lname']}",
            "workerEmail": worker['email'],
            "patientName": user['name'],
            "patientId": user['public_id'],
            "patientEmail": user['email'],
            "message": form['message'],
            "title": form['title'],
            "eventDate": datetime.strptime(
                form['date'], "%Y-%m-%dT%H:%M"),
            "isDone": False,
            "dateCreated": datetime.utcnow(),
            "eventId": uuid4().hex
        }
        # adding the message to the database
        mongo.db.appointments.insert(booking)

    # helper function for getting appointments
    @staticmethod
    def bookings(pid):
        return mongo.db.appointments.find({'patientId': pid, 'isDone': False})

    # helper function for getting appointments
    @staticmethod
    def pastBookings(pid):
        return mongo.db.appointments.find({'patientId': pid, 'isDone': True})
