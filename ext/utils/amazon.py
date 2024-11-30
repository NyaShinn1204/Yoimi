class Prime_downloader:
    def __init__(self, session):
        self.session = session
    def authorize(self, email, password):
        print(email, password)