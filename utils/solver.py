import time
import cv2
import numpy as np
import json
import curl_cffi.requests
import threading
import os
import structlog

logger = structlog.get_logger()

class PuzzleSolver:
    def __init__(self, img_data, debug=False):
        self.debug = debug
        if debug:
            os.makedirs("debug", exist_ok=True)
        
        self.img = cv2.imdecode(np.frombuffer(img_data, np.uint8), cv2.IMREAD_COLOR)
        if self.img is None:
            raise ValueError("PuzzleSolver: failed to decode image data")
        
        height, width = self.img.shape[:2]
        self.right_half = self.img[:, width//2:]
        
        if debug:
            cv2.imwrite("debug/right_half.png", self.right_half)

    def solve(self):
        try:
            gray = cv2.cvtColor(self.right_half, cv2.COLOR_BGR2GRAY)
            _, binary_mask = cv2.threshold(gray, 50, 255, cv2.THRESH_BINARY_INV)
            
            contours, _ = cv2.findContours(binary_mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
            
            if not contours:
                return 50
            
            largest_contour = max(contours, key=cv2.contourArea)
            x, y, w, h = cv2.boundingRect(largest_contour)
            center_x = x + w // 2
            
            coordinate = int((center_x / self.right_half.shape[1]) * 100)
            
            if self.debug:
                debug_img = self.right_half.copy()
                cv2.rectangle(debug_img, (x, y), (x + w, y + h), (0, 255, 0), 2)
                cv2.line(debug_img, (center_x, 0), (center_x, debug_img.shape[0]), (255, 0, 0), 2)
                cv2.putText(debug_img, f"{coordinate}", (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (255, 255, 255), 1)
                cv2.imwrite("debug/detection_result.png", debug_img)
                logger.info(f"PuzzleSolver: center_x={center_x}, coordinate={coordinate}")
            
            return max(0, min(100, coordinate))
            
        except Exception as e:
            raise Exception(f"PuzzleSolver.solve failed: {str(e)}")

class Solver:
    def __init__(self, session):
        self.session = session

    def solve_captcha(self, huid):
        try:
            response = self.session.get('https://discadia.com/api/s-captcha/')
            if response.status_code != 200:
                raise Exception(f"solve_captcha: GET request failed with status {response.status_code}")
            
            jwt_token = response.headers.get("x-token")
            if not jwt_token:
                raise Exception("solve_captcha: x-token header missing from response")
            
            puzzle_solution = PuzzleSolver(response.content).solve()
            
            payload = json.dumps({"token": jwt_token, "guess": puzzle_solution, "huid": huid})
            response = self.session.post('https://discadia.com/api/s-captcha/', data=payload)
            
            if response.status_code != 200:
                raise Exception(f"solve_captcha: POST request failed with status {response.status_code}")
            
            try:
                response_data = response.json()
            except json.JSONDecodeError as e:
                raise Exception(f"solve_captcha: invalid JSON response - {str(e)}")
            
            captcha_token = response_data.get("captcha_token")
            if captcha_token:
                return captcha_token
            else:
                raise Exception("solve_captcha: captcha_token not found in response")
                
        except Exception as e:
            raise Exception(f"solve_captcha failed: {str(e)}")

    def solve_guild_captcha(self, huid, guild_id):
        try:
            url = f'https://discadia.com/api/s-captcha/?server_id={guild_id}'
            response = self.session.get(url)
            if response.status_code != 200:
                raise Exception(f"solve_guild_captcha: GET request failed with status {response.status_code}")
            
            jwt_token = response.headers.get("x-token")
            if not jwt_token:
                raise Exception("solve_guild_captcha: x-token header missing from response")
            
            puzzle_solution = PuzzleSolver(response.content).solve()
            
            payload = json.dumps({
                "token": jwt_token, 
                "guess": puzzle_solution, 
                "huid": huid, 
                "server_id": str(guild_id)
            })
            response = self.session.post('https://discadia.com/api/s-captcha/', data=payload)
            
            if response.status_code != 200:
                raise Exception(f"solve_guild_captcha: POST request failed with status {response.status_code}")
            
            try:
                response_data = response.json()
            except json.JSONDecodeError as e:
                raise Exception(f"solve_guild_captcha: invalid JSON response - {str(e)}")
            
            captcha_token = response_data.get("captcha_token")
            if captcha_token:
                return captcha_token
            else:
                raise Exception("solve_guild_captcha: captcha_token not found in response")
                
        except Exception as e:
            raise Exception(f"solve_guild_captcha failed: {str(e)}")

    def solve(self):
        for attempt in range(1, 16):
            try:
                return self.solve_captcha("b222b60a-f9ce-4057-84f1-a6b8c7326243")
            except Exception as e:
                logger.warning(f"Solve attempt {attempt}/15 failed: {str(e)}")
                if attempt < 15:
                    time.sleep(1)
        return None

    def solve_guild(self, huid, guild_id):
        for attempt in range(1, 16):
            try:
                return self.solve_guild_captcha(huid, guild_id)
            except Exception as e:
                logger.warning(f"Guild solve attempt {attempt}/15 failed: {str(e)}")
                if attempt < 15:
                    time.sleep(1)
        return None

if __name__ == "__main__":
    session = curl_cffi.requests.Session(impersonate="chrome136")
    session.headers.update({
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,/;q=0.8,application/signed-exchange;v=b3;q=0.7',
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
    })
    solver = Solver(session)
    result = solver.solve()
    logger.info(f"Final captcha result: {result}")