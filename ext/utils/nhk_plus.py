import jwt
import ast
import uuid
import base64
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse, parse_qs, unquote, urljoin

class NHKplus_utils:
    def parse_private_key():
        # Haha! Crack from Moblie App.
        # NHK+ is suck
        
        encrypted_data = "tybiFUcVO20cZj+SYxhvOAl9Gg/CGsC6GU3l8Nsn6b+RBJ85yDgrwDK941ZCWQ9jTpQcDwxlV5/R\nsfD9gOaam8DPgsDkT31WxVuq98HN2mNMTZKQ1nAO07QPXAMnrrNkAzUZE8+jUPIUUgdX+V3+TD+a\nyGGZ2W1UjUjp9h3z/PdZjVdX8DVvPyYGuUdJ/Mc89UsXyiReJwVLGe7v1dEVF0xQJP4T9hNb6eHw\nFplVwdtAzh1ID4PsNnTwRg/+FdqCqn3FD5/o+3CimIITgakSijpjdaCWnwbor/GR+9Xvzlae5R7L\neKJgEhKfJ4aSAHRtxG40VR94Plo7EuxMaUMptwLSM7NMq6BCUyyDIlHmscueQ0xEQMZnuuuhYy1K\nA2Ql0HeO2iPJ3AWQbqhKi0ls1boz4QJXcY7BfZscoSxP1U5dmkyleE+kExpMrsrqWQWgCYKSm9lv\nXavtwWejId+IvXMp16ROcnaO8tKAmMgD8gUZN8Zdw/qVfGKNXq7oEVRP39O6WyK8yGiiryBe12Cm\nH+i6Ptr9ae+TuDTTyrDIdEG4/T4hyPd4MTabMzaIZY66k6amnBi0iYHRhYAxykMkKiaTKBZ0YR7W\nR3UpAspvdrx0UxQe3+vkk0D9n8Z+TSJWDhrx4Pf+8EVizM3ygJob6moOmWhAv/fhcPrd+wHYSjOp\nnqVh/lbAzfibpUBk4R+cEoFJ0FumFjFQ5CAOYLPGpbnHZUPrLh1nnMrCBl+GtH2Nz9ai8AuYzWI8\nM9fGcnTqPz1sWxq10LrRfB/twOe7tRHZKDSCmSZHPR2Vbb+b29NWiOHxzfslVhuoPipkal8tYzUf\nQvsFtk5akaKX85b11A2a0asr5Lz1t6nO6te3ARQ5sThFLEo4HzIfh8sgPcO0EBM/5gyqtyh60eT+\nFa3SngHuvuXIfLXxEGpKfDRIrVZ9bT8VZ95crmJUMGYGpdxQNQJPITfVSYF4tPeMVhQVH5Yh6TlI\nBJHoqlUsl8ACtZOyKqIvkdvrW1yYm7SQcDob53Y7KZQwi2VfteUj7OMtWQZhRFrtIng8JF8EiyJD\nrYuEwEwd2yQfhd0kB8OMLswwL00/ZbUYOUQIFSQyEkmL50yyILQhzQ8YrMpZNI37XqqtfOTCYQpu\nQnFQ9KmA1Oq5CsrjgiFybbhM8RWz11Zc8SrzJd8hfdpEb9IoSzLdQBu3IdtKrUIuQ2ZWFEQSGm9I\nHeERr9f3EzhKGL/6rI9aZydeIQU7ndninHGTcBN+tMKApRtAwbNyeEdTpqVnXLp6GDVwU+SAv/BB\n1Z/e1jnDXbYdh0pL/3f8i0k8+Wd4Bbkhb4218tWH/7TnKo+vE7bMj4B3HGNvhov43ezbKhAsHZ1N\nF80cqsWIes8SkVqlo9Z3yd8JVlRt1Bb34xUWQEXqhcK+3cgY1nLbbqrx4uiYPZv0f2Vx1QD4C4go\nQeEokGwYft3wQ/vkamyU1K2TLqCLT8YkP6wG2wQD4FHk0mSngSDR/3dFNUQIfAAAIskOLIumFsg5\n4Idf9bt6LsF/J4tDvxXZKXe8hmZ01G22PKyJN07q5E7x1tInZl4ms5myR/CjDwvOdmEs3dGv1Wf2\n2JzJrX+JgzcCf2He7f4NJtiJzyil0AH1riXufHilPavA3FIAR3jeiXpPxyM6ZLX1ywgJegmqK5Li\nnJydepFQ6ot8Y3LH7yJYv0MXge2QI4eUScXRCCK1lAcwVOtLgrGterOZJaLD8rBtxqLKFXaaIE9h\ng9P5awHNKVYe3y+gDVnG/0S9aIWHju2P5C0WXy6X7uqSMVMH49ypMS+V8B73MJNWF+sZyLmb8Ew6\nuqc7yf3y51y4laRmYLo6qhM1MyDsUsVHceYeK5yx/w3aYhJAeJl8FDYoqFIedPsSut9CU/E74Ak8\nICORgHEtCcgcZqUkR5j7uMPCRV7jVJ0KDblF8Bub0M4UrHZpu7ZKaq+4FEXAvEcFjJjViftmiIyL\nRaTnp6LXCH6GPj2bBxevOynqJLi8EnI35wDZ4yTWxwsoxt9tAD6EFqe7O9KNNWaX6MrHSYvGO1ln\nKwc0j7sRfw94VtEhmf9TJY5fK38EkKWXVwVzFON/jhbhoqBODA9yvvA3BVR1SRwlmFCiHHVNOy0d\n9LsiyQ==" # Crack from Moblie res/res.xml lol
        
        iv = base64.b64decode('3vh8IpHEcjJYUYhobRBcsQ==')  # IV
        key = base64.b64decode('tK1rb8W9cDAVvf1zKDXVYw==')  # Key
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(base64.b64decode(encrypted_data)), AES.block_size)
        
        header = "-----BEGIN RSA PRIVATE KEY-----\n"
        footer = "\n-----END RSA PRIVATE KEY-----"
        
        return_dec = decrypted.decode('utf-8')
        return_dec = header + return_dec + footer
                
        return return_dec

class NHKplus_downloader:
    def __init__(self, session, logger):
        self.session = session
        self.logger = logger
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
        self.common_headers = {
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
            "Sec-GPC": "1",
            "Accept-Language": "ja;q=0.7",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-User": "?1",
            "Sec-Fetch-Dest": "document",
            "Sec-CH-UA": "\"Brave\";v=\"131\", \"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\"",
            "Sec-CH-UA-Mobile": "?0",
            "Sec-CH-UA-Platform": "\"Windows\"",
            "Accept-Encoding": "gzip, deflate, br, zstd",
        }
    def authorize(self, email, password):
        try:
            # Step 1-5: Initial redirects and parameter extraction
            url = "https://pid.nhk.or.jp/account/update/info.do"
            for _ in range(5):  # Combined redirect handling
                response = self.session.get(url, headers=self.common_headers, allow_redirects=False)
                if response.status_code not in (301, 302):
                    break #exit the loop if there is no redirect
                url = response.headers["Location"]
                if "login.auth.nhkid.jp" in url: #special case for login redirect
                    break
                self.logger.debug(f"Redirect: {response.status_code} to {url}", extra={"service_name": "NHK+"}) #print redirect status
            else:
                raise Exception("Too many redirects or no redirect URL found.")
            
            if "login.auth.nhkid.jp" in url: #special case for login redirect
                parsed_url = urlparse(url)
                parameters = parse_qs(parsed_url.query)
                response_parameter = {key: value[0] for key, value in parameters.items()}
            else:
                raise Exception("Did not arrive at login URL")
            
            # Step 6: Initial Login Request
            url = "https://login.auth.nhkid.jp/auth/login"
            payload = {
                "AUTH_TYPE": "AUTH_OP",
                "SITE_ID": "co_site",
                "MESSAGE_AUTH": response_parameter["MESSAGE_AUTH"],
                "AUTHENTICATED": response_parameter["AUTHENTICATED"],
                "snsid": "undefined",
                "Fingerprint": str(uuid.uuid4())
            }
            headers = self.common_headers.copy()
            headers.update({
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": "https://login.auth.nhkid.jp",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Accept": "application/json, text/plain, */*",
            })
            response = self.session.post(url, data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 1: {response.status_code}", extra={"service_name": "NHK+"})

            # Step 7: Authentication with Email and Password
            payload = {
                "ORG_ID": "undefined",
                "ID": email,
                "PWD": password,
                "user-agent": self.user_agent,
                "PIN_CODE": "undefined",
                "Fingerprint": str(uuid.uuid4()),
                "lowLevelSessionFlg": "undefined"
            }
            response = self.session.post(url, data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 2: {response.status_code}", extra={"service_name": "NHK+"})

            if response.json()["resultCode"] != "CO-SC0003":
                raise Exception(f"Login failed: {response.json().get('resultMessage', 'Unknown error')}")

            # Step 8-11: Final redirects and data retrieval
            formatted_url = f"{urlparse(response.json()['authenticated']).scheme}://{urlparse(response.json()['authenticated']).netloc}{urlparse(response.json()['authenticated']).path}?{unquote(urlparse(response.json()['authenticated']).query)}"
            url = formatted_url
            for i in range(4):
                response = self.session.get(url, headers=self.common_headers, allow_redirects=False)
                if response.status_code not in (301, 302):
                    break #exit the loop if there is no redirect
                if i == 0:
                    url = "https://agree.auth.nhkid.jp"+response.headers["Location"]
                else:
                    url = response.headers["Location"]
                self.logger.debug(f"Redirect: {response.status_code} to {url}", extra={"service_name": "NHK+"}) #print redirect status
            else:
                raise Exception("Too many redirects or no redirect URL found.")

            find_soup = BeautifulSoup(response.text, "html.parser")
            token = find_soup.find("input", {"name": "t"})["value"]

            url = "https://pid.nhk.or.jp/pid26/repassword.do"
            payload = {"pass": password, "t": token}
            headers = self.common_headers.copy()
            headers.update({
                "Origin": "https://pid.nhk.or.jp",
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": "https://pid.nhk.or.jp/account/update/info.do",
            })
            response = self.session.post(url, data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Password reset check: {response.status_code}", extra={"service_name": "NHK+"})


            url = "https://pid.nhk.or.jp/pid23/getPCSummaryListAll3.do"
            response = self.session.get(url, headers=self.common_headers)
            self.logger.debug("GET USER INFO: "+str(response.text), extra={"service_name": "NHK+"})

            response = self.session.get("https://hh.pid.nhk.or.jp/pidh01/portal/getMemInfo.do?callback=USER_INFO")
            data = response.text.replace("true", "True")
            json_part = data[data.find("(") + 1: data.rfind(")")]
            parsed_json = ast.literal_eval(json_part)
            self.logger.debug("GET USER INFO2: "+str(parsed_json), extra={"service_name": "NHK+"})

            return True, parsed_json # Return the user info

        except Exception as e:
            self.logger.debug(f"An error occurred: {e}", extra={"service_name": "NHK+"})
            return False, e  # Or raise the exception if you prefer

    def create_access_token(self, email, password):
        try:
            headers = self.common_headers.copy()
            headers.update({
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": "https://agree.auth.nhkid.jp",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Accept": "application/json, text/plain, */*",
            })
            payload = {
                "scope": "openid SIMUL001",
                "response_type": "id_token token",
                "client_id": "simul",
                "redirect_uri": "https://plus.nhk.jp/auth/login",
                "claims": "{\"id_token\":{\"service_level\":{\"essential\":true}}}",
                "prompt": "login",
                "nonce": str(uuid.uuid4()),
                "state": "/watch/ch/g1",
                "did": str(uuid.uuid4())
            }

            response = self.session.get("https://agree.auth.nhkid.jp/oauth/AuthorizationEndpoint?", params=payload, headers=headers, allow_redirects=False)

            response = self.session.get(response.headers["Location"], headers=headers, allow_redirects=False)
            headers = self.common_headers.copy()
            headers.update({
                "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
                "Origin": "https://login.auth.nhkid.jp",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Dest": "empty",
                "Accept": "application/json, text/plain, */*",
            })
            parsed_url = urlparse(response.headers["Location"])
            parameters = parse_qs(parsed_url.query)
            response_parameter = {key: value[0] for key, value in parameters.items()}
            payload = {
                "AUTH_TYPE": "AUTH_OP",
                "SITE_ID": "co_site",
                "MESSAGE_AUTH": response_parameter["MESSAGE_AUTH"],
                "AUTHENTICATED": response_parameter["AUTHENTICATED"],
                "snsid": "undefined",
                "Fingerprint": str(uuid.uuid4())
            }
            response = self.session.post("https://login.auth.nhkid.jp/auth/login", data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 1: {response.status_code}", extra={"service_name": "NHK+"})

            # Step 7: Authentication with Email and Password
            payload = {
                "ORG_ID": "undefined",
                "ID": email,
                "PWD": password,
                "user-agent": self.user_agent,
                "PIN_CODE": "undefined",
                "Fingerprint": str(uuid.uuid4()),
                "lowLevelSessionFlg": "undefined"
            }
            response = self.session.post("https://login.auth.nhkid.jp/auth/login", data=payload, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 2: {response.status_code}", extra={"service_name": "NHK+"})

            if response.json()["resultCode"] != "CO-SC0003":
                self.logger.info(f"Login failed: {response.json().get('resultMessage', 'Unknown error')}", extra={"service_name": "NHK+"})
                raise Exception()

            # Step 3 (Corrected): Handle the redirect and extract parameters
            # The 'authenticated' value contains a URL, sometimes relative.
            authenticated_url = response.json()["authenticated"]
            if not authenticated_url.startswith("http"): # Check if the URL is relative
                authenticated_url = urljoin("https://login.auth.nhkid.jp", authenticated_url) # Join relative URL with base URL
            response = self.session.post(authenticated_url, headers=headers, allow_redirects=False)
            self.logger.debug(f"Login Step 3: {response.status_code}", extra={"service_name": "NHK+"})

            parsed_url = urlparse(response.headers["Location"])
            fragment = parsed_url.fragment
            query_params = parse_qs(fragment)
            for key, value in query_params.items():
                self.logger.debug(f"+ {key}: {value[0]}", extra={"service_name": "NHK+"})
            id_token = query_params.get("id_token", [None])[0]

            return True,  "Bearer " + id_token
        except Exception as e:
            self.logger.debug(f"An error occurred: {e}", extra={"service_name": "NHK+"})
            return False, e  # Or raise the exception if you prefer
    def gen_access_token(self):        
        private_key = NHKplus_utils.parse_private_key()
            
        payload = {
            "iss": "app.nhkplus",
            "sub": "AppToken",
            "aud": "ctl.npd.plus.nhk.jp",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc)
        }
        
        headers = {
            "kid": "008b6857-3801-492c-bc50-48531db4b936",
            "alg": "RS256",
        }
        
        token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
        
        return  "Bearer " + token
    
    def get_drm_token(self, token):
        accesskey_json = self.session.post("https://ctl.npd.plus.nhk.jp/create-accesskey", json={}, headers={"Authorization": token}).json()
        
        return accesskey_json["drmToken"]