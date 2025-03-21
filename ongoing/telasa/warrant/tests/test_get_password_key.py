import unittest
import base64
import datetime
import hmac
import hashlib
import re

from warrant import aws_srp

class TestGetPasswordKey(unittest.TestCase):
   """Test suit for Warrant module"""
   def __init__(self, methodName: str = "runTest") -> None:
      self.username = 'yu.zhu'
      self.password = 'Password!@1'
      self.user_pool_id = 'ap-southeast-2_hLL8uaLCg'
      self.client_id = '1c6i3f31fot517i1l2m1d7rt3a'
      self.SRP_B = '924edbc9fb3439f7994cd7cd114da82b92429ea1c54d53bf6551b4bc70f9eba35ab6266b127e4ce2eb0cf33613f15ab96bb4e4f4950f23386e1fac0658a81ee95065b07e15c58a4ebf7123997f56e7ecfdf857013c22cab99cd576e675182153376711e120808b220198aa7a76f1c063034f3a536add67862aab9716fd5ce5539aca2d9a20c5887f977b97f837a69b39f1198fb5a96f9f60925e48e4959e31e0d9cc222e6d7ef2fb3f8397d3cb043d7a389733bf27475769a4d5303cc4cbb368aeeb5891b58250bf6801524c51b1b2d305fb5d0529dc70367eae25c110ba3b4a29df34c7120c3be6d57882af36aae0ff2ee78ec12ed007b9bce64224d09fcb4383611a8423bd2933e4e90899d44b2965f6eed05f3e83f91d1ac102c6de536b46b0e719605e9db9e9333393edba67045b19cb22680a0ac55cdaa5a22e01e1c27b46a765cb4e2df750888338f938467f19c6db6bf763260ccebcb7fdaae954ac4f3b5905c6d8dd44b518d92fba1eb97e68a4a4866287b016fddc56b2bc756a9254'
      self.SALT = '752666a2a2b98c9012db86f9ca5344d0'
      self.SECRET_BLOCK = '4iRTnDcV885dMpffl+vm2PiwAJpTTbujVBqAkQ2p3XzkOEmSJ0fCd7CY9Z30m3O7+wqYborAIjai98kJZEnu5FxCsBrJbC67n9n47s9GVzYx1QFmLcI/z0bgG3LYpR9DyWhS0EFS0yoNDKJZdW5OiI25nBAKsbLCFigwxYAmPrMIblhQz/jVq6wH4a8EZZZ8zUgI/nFEx1UTWrHvAXPUL8mQdQ7+i0OTh0NRKA+W/9ba1pFdWOj4rQ8Rf6/dA2xMxdyGBAxfn8kyU3Yl2pVBxmYpqBPKV637gsFgMAzhiK+1Z6zRCg3Ck6QKkPdLjwPGAGkleVhD3IzJfhn0MgPaNzGWNvMUnvTCMPMY5UzzelqfF3ZTiSs0MJPt6BiJEvuSmHuAZZuPxGg53+8+ZTa0JV9zKQrSJyATq9nnTQx0BBEV8OIBj/imGZYMnEFnLLmZ1+SALfhGefQOJ26klTPVEwDZook9YAvqP5TvhFkP/y7+Htzl8Hh8vrmp9qq6eIFbeGlDUpp6PXwdfQa+Rlm87q8WP+biTMmGn+CjjKZZZi2oxm8Xos3ZCuxiNWVOkeuy+1BxLIdYgqkRRSoJnA1PPgRz2Hrdxn+j94U/tUQSbZjiTop3j7jpto0tcut1qh+FXWewBLlqne694t7sT0OcVkcCIQjtb8fJI776fs7/4cBbXMhN+xWltIwzInRRYIeqSbG74T2UFCESB8o7jNRZdV3sSwEzTLd0quGnCq5b/Q7Ek9oLoxVuraaN95IDBu90OtldhqbjJAhUVrKh8UpeoH8XOm25m5Ib1u9y1Ev8K4LNDcvlTWsKnwvXFDUtsmkEua1IH3XMJ1xesq3TUPvd6k9/pQMy5wycnCEOgsQgZWSOecVA4020lA0h5kaWMssIN4h0ioqsLX7lWT7YO8sigdXO+ESTydBQX2JRlcql8jYgI8c4rMlUaXpvfaR8u5lgw6RoP4hc5r+JEgEUjPy09cbdTgRQbTRJ03vB/XX+Af18O/HpcgnTX9gFDSjQOMMFQgBI/RiaJMsx5pPymBxxzScZg3GKzoPqSVTOINpX8alGUMJdd/ekK6eBX/nk4Id3ihSh1xEbIn0DxvthULGySW/Cu7/ltRWlEplAAKzzM7UxNd4Y5WE0QnnkOHG4KCUwIxckF1htEj9bb0b9xd6H8oRuniDo9aRhVZIruVyLn2jENq5fMtEFdGKrmo0VM1FHqr+/MEjQRdjBW89pxgfAYRf3AuyFoBFeuowIOlnmK+EvX5UVBwlAtMYVePAHT1YjqhV96tfqDJnFuEplQfzpRBMocUKD4Ik='
      super().__init__(methodName)

   def setUp(self):
      """Set up for each test"""
      self.AWSSRP = aws_srp.AWSSRP(username=self.username, password=self.password, \
         pool_id=self.user_pool_id, client_id=self.client_id )

   def test_get_password_authentication_key(self):
      """Test get_password_authentication_key method"""

      M = self.AWSSRP.get_password_authentication_key(self.username, self.password, \
         aws_srp.hex_to_long(self.SRP_B), \
         self.SALT)
      self.assertIsNotNone(M)

   def test_create_signature(self):
      """Test create signature string"""

      hkdf = self.AWSSRP.get_password_authentication_key(self.username, self.password, \
         aws_srp.hex_to_long(self.SRP_B), \
         self.SALT)
      timestamp = re.sub(r" 0(\d) ", r" \1 ",
                  datetime.datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y"))

      secret_block_bytes = base64.standard_b64decode(self.SECRET_BLOCK)
      msg = bytearray(self.user_pool_id.split('_')[1], 'utf-8') + bytearray(self.username, 'utf-8') + \
            bytearray(secret_block_bytes) + bytearray(timestamp, 'utf-8')
      hmac_obj = hmac.new(hkdf, msg, digestmod=hashlib.sha256)
      signature_string = base64.standard_b64encode(hmac_obj.digest())

      print(signature_string.decode('utf-8'))
