import json
import time
import os
import threading
import curl_cffi.requests
from utils.solver import Solver
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import binascii
import re
import structlog
import random_strings
import random

logger = structlog.get_logger()
file_lock = threading.Lock()

def save_token(token, status):
    files = {
        "success": "successful.txt",
        "failed": "failed.txt", 
        "banned": "banned_token.txt",
        "already_voted": "already_voted.txt"
    }
    
    if status not in files:
        return
    
    with file_lock:
        with open(files[status], 'a') as f:
            f.write(f"{token}\n")

def decrypt_cookie(key_hex, iv_hex, data_hex):
    key = binascii.unhexlify(key_hex)
    iv = binascii.unhexlify(iv_hex)
    data = binascii.unhexlify(data_hex)
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    
    return binascii.hexlify(decrypted).decode()

class BannedTokenException(Exception):
    pass

class DiscordAuth:
    def __init__(self):
        self.session = curl_cffi.requests.Session(impersonate="chrome136")
        self.session.headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'pragma': 'no-cache',
            'priority': 'u=0, i',
            'referer': 'https://discadia.com/login/?next=/',
            'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'upgrade-insecure-requests': '1',
            'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
        }
        
        session_id = random_strings.random_string(8)
        proxy_url = f"http://Lf6QORbXxY33XdUR:m6zy5lNykBfFRa9S_country-de_session-{session_id}_lifetime-30m@geo.iproyal.com:12321"
        self.session.proxies = {"http": proxy_url, "https": proxy_url}

    def _extract_encryption_params(self, html):
        pattern = r'e\("([a-f0-9]{32})"\)'
        matches = re.findall(pattern, html)
        if len(matches) < 3:
            raise Exception(f"extract_encryption_params: found {len(matches)}/3 parameters")
        return matches[0], matches[1], matches[2]

    def _extract_csrf_token(self, html):
        if '"csrf_token" content="' not in html:
            raise Exception("extract_csrf_token: csrf token not found in HTML")
        return html.split('"csrf_token" content="')[1].split('"')[0]

    def get_session(self):
        try:
            resp = self.session.get('https://discadia.com/auth/discord-captcha/?next=/')
            if resp.status_code != 200:
                raise Exception(f"get_session: initial GET failed with {resp.status_code}")
            
            key, iv, encrypted = self._extract_encryption_params(resp.text)
            cookie = decrypt_cookie(key, iv, encrypted)
            self.session.cookies.update({'_cosmic_auth': cookie})
            
            resp = self.session.get('https://discadia.com/auth/discord-captcha/?next=/')
            if resp.status_code != 200:
                raise Exception(f"get_session: second GET failed with {resp.status_code}")
            
            csrf_token = self._extract_csrf_token(resp.text)
            
            logger.info("Solving login captcha")
            solver = Solver(self.session)
            captcha_token = solver.solve()
            
            if not captcha_token:
                raise Exception("get_session: captcha solve failed")
            
            logger.info("Login captcha solved")
            
            sessionid = self.session.cookies.get_dict().get("discadia_sessionid")
            if not sessionid:
                raise Exception("get_session: session ID not found in cookies")
            
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'next': '/',
                'session_key': sessionid,
                'captcha_token': captcha_token,
                'session_timestamp': str(time.time()).split(".")[0],
                'prevent_loop': 'true',
                'browser_debug': '{"userAgent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36","cookieEnabled":true,"platform":"Linux x86_64","language":"en-US","doNotTrack":null,"hasLocalStorage":true,"hasSessionStorage":true,"hasCookies":true,"cookieLength":120}',
            }

            resp = self.session.post('https://discadia.com/auth/discord-captcha/', data=data)
            if resp.status_code != 200:
                raise Exception(f"get_session: POST failed with {resp.status_code}")
            
            if "state=" not in resp.url:
                raise Exception("get_session: no state parameter in response URL")
            
            return resp.url.split("state=")[1]
            
        except Exception as e:
            raise Exception(f"get_session failed: {str(e)}")

    def auth_discord_token(self, token, session_state):
        try:
            self.session.headers = {
                'accept': '*/*',
                'accept-language': 'en-US,en;q=0.9',
                'authorization': token,
                'cache-control': 'no-cache',
                'content-type': 'application/json',
                'origin': 'https://discord.com',
                'pragma': 'no-cache',
                'priority': 'u=1, i',
                'referer': f'https://discord.com/oauth2/authorize?client_id=423718605226639361&redirect_uri=https%3A%2F%2Fdiscadia.com%2Faccounts%2Fdiscord%2Flogin%2Fcallback%2F&scope=guilds+identify+email&response_type=code&state={session_state}',
                'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Linux"',
                'sec-fetch-dest': 'empty',
                'sec-fetch-mode': 'cors',
                'sec-fetch-site': 'same-origin',
                'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
                'x-debug-options': 'bugReporterEnabled',
                'x-discord-locale': 'en-US',
                'x-discord-timezone': 'America/New_York',
                'x-super-properties': 'eyJvcyI6IkxpbnV4IiwiYnJvd3NlciI6IkNocm9tZSIsImRldmljZSI6IiIsInN5c3RlbV9sb2NhbGUiOiJlbi1VUyIsImhhc19jbGllbnRfbW9kcyI6ZmFsc2UsImJyb3dzZXJfdXNlcl9hZ2VudCI6Ik1vemlsbGEvNS4wIChYMTE7IExpbnV4IHg4Nl82NCkgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzEzNy4wLjAuMCBTYWZhcmkvNTM3LjM2IiwiYnJvd3Nlcl92ZXJzaW9uIjoiMTM3LjAuMC4wIiwib3NfdmVyc2lvbiI6IiIsInJlZmVycmVyIjoiIiwicmVmZXJyaW5nX2RvbWFpbiI6IiIsInJlZmVycmVyX2N1cnJlbnQiOiIiLCJyZWZlcnJpbmdfZG9tYWluX2N1cnJlbnQiOiIiLCJyZWxlYXNlX2NoYW5uZWwiOiJzdGFibGUiLCJjbGllbnRfYnVpbGRfbnVtYmVyIjo0MTY2MTMsImNsaWVudF9ldmVudF9zb3VyY2UiOm51bGwsImNsaWVudF9sYXVuY2hfaWQiOiI2OGU3NjljMy1iZTY5LTRiNjctYTFhMi1hYWM5N2I2N2ViY2UiLCJjbGllbnRfYXBwX3N0YXRlIjoiZm9jdXNlZCJ9',
            }

            params = {
                'client_id': '423718605226639361',
                'response_type': 'code',
                'redirect_uri': 'https://discadia.com/accounts/discord/login/callback/',
                'scope': 'guilds identify email',
                'state': session_state,
            }

            json_data = {
                'permissions': '0',
                'authorize': True,
                'integration_type': 0,
                'location_context': {
                    'guild_id': '10000',
                    'channel_id': '10000',
                    'channel_type': 10000,
                },
                'dm_settings': {
                    'allow_mobile_push': False,
                },
            }

            resp = self.session.post('https://discord.com/api/v9/oauth2/authorize', params=params, json=json_data)
            
            if resp.status_code == 401:
                raise BannedTokenException("auth_discord_token: token banned/invalid (401)")
            elif resp.status_code != 200:
                raise Exception(f"auth_discord_token: Discord API returned {resp.status_code}")
            
            try:
                resp_data = resp.json()
            except json.JSONDecodeError as e:
                raise Exception(f"auth_discord_token: JSON decode failed - {str(e)}")
            
            location = resp_data.get("location")
            if not location:
                raise Exception("auth_discord_token: no location in Discord response")
            
            return location
            
        except BannedTokenException:
            raise
        except Exception as e:
            raise Exception(f"auth_discord_token failed: {str(e)}")

    def _extract_vote_params(self, html, server_name):
        if "You can vote again in" in html:
            return None, None, None, True
        
        patterns = {
            'csrf': '"csrf_token" content="',
            'huid': 'huid="',
            'server_id': 'server-id="'
        }
        
        for key, pattern in patterns.items():
            if pattern not in html:
                raise Exception(f"extract_vote_params: {key} not found in vote page")
        
        csrf_token = html.split(patterns['csrf'])[1].split('"')[0]
        huid = html.split(patterns['huid'])[1].split('"')[0]
        server_id = html.split(patterns['server_id'])[1].split('"')[0]
        
        return csrf_token, huid, server_id, False

    def vote_server(self, server_name):
        try:
            self.session.headers = {
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'pragma': 'no-cache',
                'priority': 'u=0, i',
                'referer': f'https://discadia.com/server/{server_name}/',
                'sec-ch-ua': '"Google Chrome";v="137", "Chromium";v="137", "Not/A)Brand";v="24"',
                'sec-ch-ua-mobile': '?0',
                'sec-ch-ua-platform': '"Linux"',
                'sec-fetch-dest': 'document',
                'sec-fetch-mode': 'navigate',
                'sec-fetch-site': 'same-origin',
                'sec-fetch-user': '?1',
                'upgrade-insecure-requests': '1',
                'user-agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            }
            
            resp = self.session.get(f'https://discadia.com/vote/{server_name}/')
            if resp.status_code != 200:
                raise Exception(f"vote_server: GET vote page failed with {resp.status_code}")
            
            csrf_token, huid, server_id, already_voted = self._extract_vote_params(resp.text, server_name)
            
            if already_voted:
                return "already_voted"
            
            logger.info("Solving guild captcha")
            solver = Solver(self.session)
            captcha_token = solver.solve_guild(huid, server_id)
            
            if not captcha_token:
                raise Exception("vote_server: guild captcha solve failed")
            
            logger.info("Guild captcha solved")
            
            data = {
                'csrfmiddlewaretoken': csrf_token,
                'captcha_token': captcha_token,
                'browser_data': json.dumps({"ts":int(str(time.time()).split('.')[0]),"kp":False,"mm":True}),
            }

            resp = self.session.post(f'https://discadia.com/vote/{server_name}/', data=data)
            if resp.status_code != 200:
                raise Exception(f"vote_server: POST vote failed with {resp.status_code}")
            return "success" if 'You can vote again in' in resp.text else "failed"
            
        except Exception as e:
            raise Exception(f"vote_server failed: {str(e)}")

    def vote_from_account(self, token, server_name):
        try:
            session_state = self.get_session()
            auth_url = self.auth_discord_token(token, session_state)
            
            get_cookies = self.session.get(auth_url)
            if get_cookies.status_code != 200:
                raise Exception(f"vote_from_account: callback GET failed with {get_cookies.status_code}")
            
            logger.info(f"{token[:20]} logged in successfully")
            
            vote_result = self.vote_server(server_name)
            
            if vote_result == "success":
                logger.info(f"{token[:20]} voted successfully for {server_name}")
                return "success"
            elif vote_result == "already_voted":
                logger.info(f"{token[:20]} already voted for {server_name}")
                return "already_voted"
            else:
                logger.error(f"{token[:20]} vote failed for {server_name}")
                return "failed"
                
        except BannedTokenException:
            logger.error(f"{token[:20]} token is banned")
            return "banned"
        except Exception as e:
            logger.error(f"{token[:20]} error: {str(e)}")
            return "failed"

def read_file(filename):
    try:
        if not os.path.exists(filename):
            logger.error(f"File {filename} not found")
            return []
            
        with open(filename, 'r') as f:
            lines = [line.strip() for line in f.readlines() if line.strip()]
            
        logger.info(f"Loaded {len(lines)} lines from {filename}")
        return lines
        
    except Exception as e:
        logger.error(f"Error reading {filename}: {str(e)}")
        return []

def process_token(token, servers):
    logger.info(f"Processing {token[:20]}")
    
    auth = DiscordAuth()
    status = "failed"
    
    for server in servers:
        try:
            result = auth.vote_from_account(token, server)
            
            if result == "banned":
                status = "banned"
                break
            elif result == "success":
                status = "success"
            elif result == "already_voted" and status != "success":
                status = "already_voted"
            
            time.sleep(random.uniform(1, 2))
        except Exception as e:
            logger.error(f"{token[:20]} exception in process_token: {str(e)}")
            continue
    
    save_token(token, status)
    logger.info(f"{token[:20]} completed with status: {status}")

def main():
    tokens = read_file('tokens.txt')
    servers = read_file('server.txt')
    
    if not tokens:
        logger.error("No tokens found")
        return
        
    if not servers:
        logger.error("No servers found")
        return
    
    logger.info(f"Starting with {len(tokens)} tokens and {len(servers)} servers")
    
    max_threads = 50
    logger.info(f"Using {max_threads} threads")
    
    threads = []
    
    for i, token in enumerate(tokens):
        thread = threading.Thread(target=process_token, args=(token, servers))
        threads.append(thread)
        thread.start()
        
        if (i + 1) % max_threads == 0:
            for t in threads:
                t.join()
            threads = []
            logger.info(f"Processed batch {i+1-max_threads+1}-{i+1}")
            
        time.sleep(0.1)
    
    for thread in threads:
        thread.join()

    logger.info("All tokens processed")

if __name__ == "__main__":
    main()