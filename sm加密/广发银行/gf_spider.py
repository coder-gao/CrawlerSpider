import hashlib

import ddddocr
import gmssl
import requests
from gmssl import sm2, func
from loguru import logger


class Spider:
    def __init__(self, username: str, password: str):
        self.username = username
        self.password = password
        self.logger = logger
        self.requests = requests.Session()
        self.ocr = ddddocr.DdddOcr(show_ad=False)

    def login(self):
        url = "https://mall-sop.cgbchina.com.cn/api/cgb-user/web/login/seller/identify-new"
        data = {
            "encryptContent": ,
            "encryptKey":
        }
        response = self.requests.post(url, data=data)
        return response.json()['data']

    def get_encrypt_data(self, public_key:str, token: str):
        # SM4 requires a 16 byte key
        sm4_key = func.random_hex().zfill(32).upper()


        # 生成sm2和sm4的密钥
        # SM2 key pairs are generated
        sm2_crypt = sm2.CryptSM2(private_key=None, public_key=public_key)
        sm2_key_pair = sm2_crypt.encrypt(sm4_key)



        # 将加密后的数据转为十六进制字符串
        data_encrypted_hex = data_encrypted.hex().upper()

        result = {'cipherKey': sm4_key_encrypted,
                  'cipherMsg': data_encrypted_hex,
                  'cryptoKey_SM4': sm4_key}

        return result

    def encrypt_pwd(self, pwd: str):
        return hashlib.sha1(pwd.encode('utf-8')).hexdigest()

    def get_public_key(self):
        url = 'https://mall-sop.cgbchina.com.cn/api/encrypt/public-key'
        response = self.requests.get(url)
        return response.json()['data']['encryptContent']

    def ocr_captcha(self, img_base64):
        return self.ocr.classification(img_base64.replace('data:image/png;base64, ',''))

    def get_captcha(self):
        headers = {
            "Accept": "application/json",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "DNT": "1",
            "Pragma": "no-cache",
            "Referer": "https://mall-sop.cgbchina.com.cn/login",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        }
        url = "https://mall-sop.cgbchina.com.cn/api/user/web/get-captcha"
        response = self.requests.get(url, headers=headers)
        return response.json()['data']




if __name__ == '__main__':
    spider = Spider()
    captcha = spider.get_captcha()
    spider.ocr_captcha(captcha['imageUrl'])
