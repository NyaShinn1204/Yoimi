import ast
import uuid
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs, unquote

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
                self.logger.debug(i, extra={"service_name": "NHK+"})
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
            self.logger.debug("GET USER INFO:", response.text, extra={"service_name": "NHK+"})

            response = self.session.get("https://hh.pid.nhk.or.jp/pidh01/portal/getMemInfo.do?callback=USER_INFO")
            data = response.text.replace("true", "True")
            json_part = data[data.find("(") + 1: data.rfind(")")]
            parsed_json = ast.literal_eval(json_part)
            self.logger.debug("GET USER INFO2:", parsed_json, extra={"service_name": "NHK+"})

            return True, parsed_json # Return the user info

        except Exception as e:
            self.logger.debug(f"An error occurred: {e}", extra={"service_name": "NHK+"})
            return False, e  # Or raise the exception if you prefer