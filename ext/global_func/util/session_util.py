import os
import json
import time
import hashlib

class session_util:
    def __init__(self, logger, service_name, service_util):
        self.logger = logger
        self.service_name = service_name
        self.service_util = service_util
    
    
    def save_session_data(self, session_data):
        path = os.path.join("cache", "session", self.service_name.lower(), f"session_{int(time.time())}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(session_data, f, ensure_ascii=False, indent=4)    
    

    def refresh_session(self, session_data):
        self.logger.info("Session is Invalid. Refreshing...", extra={"service_name": self.service_name})
        self.service_util.refresh_token(session_data["refresh_token"], session_data)
        status, message = self.service_util.get_userinfo()
        if status:
            self.save_session_data(session_data)
            return True, message
        else:
            self.logger.error("Refresh failed. Please re-login", extra={"service_name": self.service_name})
            return False, None    
    

    def validate_normal_login(self, session_data, email, password):
        return (
            session_data["email"] == hashlib.sha256(email.encode()).hexdigest() and
            session_data["password"] == hashlib.sha256(password.encode()).hexdigest() and
            session_data["method"] == "NORMAL"
        )    
    

    def validate_qr_login(self, session_data):
        return (
            session_data["method"] == "QR_LOGIN"
        )    
    

    def login_with_credentials(self, email, password, login_method):
        if login_method == "normal":
            status, message, login_status, session_data = self.service_util.authorize(email, password)
        elif login_method == "qr":
            status, message, login_status, session_data = self.service_util.authorize_qr()
        if not status:
            self.logger.error(message, extra={"service_name": self.service_name})
            exit(1)
        self.save_session_data(session_data)
        return True, message, session_data