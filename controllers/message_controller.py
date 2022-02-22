import rsa
from flask_login import current_user
from controllers.user_controller import get_user_by_id


def create_message(body, receiver_id):
    from models import Message
    user = current_user
    message = Message(body=body, sender_id=user.id)
    receiver_id = int(receiver_id)
    receiver = get_user_by_id(receiver_id)
    message.receivers.append(receiver)
    from app import db
    db.session.add(message)
    db.session.commit()


def get_user_messages():
    recieved_messages = current_user.recv_messages

    for message in recieved_messages:
        encrypted_message = message.body
        user = current_user
        private_key = rsa.PrivateKey.load_pkcs1(user.private_key)
        data = rsa.decrypt(encrypted_message, private_key)
        data = data.decode('ascii')
        message.body = data
    return recieved_messages
