import axios from "axios";

import cryptoJS from "crypto-js";

import getLogger from "../../logger.js";
import SM2 from "./crypto/sm2.js";
import SM4 from "./crypto/sm4.js";

const logger = getLogger('gf_spider');
class Gf_spider{
    constructor(username, password){
        this.username = username;
        this.password = password;

    }

    static async get_captcha(){
        const headers = {
            "Accept": "application/json",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "DNT": "1",
            "Pragma": "no-cache",
            "Referer": "https://mall-sop.cgbchina.com.cn/login",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        };
        const url = "https://mall-sop.cgbchina.com.cn/api/user/web/get-captcha";
        const response = await axios.get(url, {headers: headers});
        return response['data']
    }

    static async ocr(img_base64){
        const response = await axios.post('http://127.0.0.1:5000/ocr', {img_base64}, {
            headers: {
                'Content-Type': 'application/json',
            },
            timeout: 5000 // 超时时间（毫秒）`
        });
        return response['data']['result']
    }

    encrypt_pwd(){
        // sha1加密
        return cryptoJS.SHA1(this.password).toString(cryptoJS.enc.Hex);
    }
    static async login(cipherKey, cipherMsg)    {
        let response = await axios.post('https://mall-sop.cgbchina.com.cn/api/cgb-user/web/login/seller/identify-new', {encryptKey, cipherMsg},{
            headers: {
                'Content-Type': 'application/json',
            },
            timeout: 5000 // 超时时间（毫秒）`
        });
        return response['data']
    }

    async get_public_key(){
        const headers = {
            "Accept": "application/json",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "DNT": "1",
            "Pragma": "no-cache",
            "Referer": "https://mall-sop.cgbchina.com.cn/login",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        };
        const url = "https://mall-sop.cgbchina.com.cn/api/encrypt/public-key";
        const response = await axios.get(url, {headers: headers});
        return response['data']['encryptContent']
    }

    encrypt_params(username, password, captcha_token, captcha_ocr,  public_key){
        let t = public_key,
            e = {
            captcha: captcha_ocr,
            identify: username,
            password: password,
            token: captcha_token
        }
        let n = new SM2
            , r = new SM4
            , o = r.generateKey().toUpperCase()
            , i = n.encrypt(t, Hex.utf8StrToHex(o))
            , a = n.cipherToC1C3C2(i)
            , c = Hex.utf8StrToBytes(JSON.stringify(e))
            , l = Hex.decode(o)
            , u = r.encrypt_ecb(l, c)
            , s = Hex.encode(u, 0, u.length);
        return {
            cipherKey: a,
            cipherMsg: s,
            cryptoKey_SM4: o
        }
    }
}


(async () => {
        const startTime = new Date().getTime();
        const spider = new Gf_spider('123', '123');
        // const resp = await Gf_spider.get_captcha(spider);
        // logger.debug(JSON.stringify(resp));
        // const captcha_txt = await Gf_spider.ocr(resp['data']['imageUrl']);
        // logger.info(captcha_txt)

        // Encrypting password
        const encryptedPassword = spider.encrypt_pwd();
        logger.info(`Encrypted Password: ${encryptedPassword}`);

        // 获取服务器返回的 public key
        // let publicKey = spider.get_public_key();

        // 对参数进行加密（用户名、密码、验证码token、public key）
        let encryptParams = spider.encrypt_params("123456",
            "dd5fef9c1c1da1394d6d34b248c51be2ad740840",
            "a72c2818-2e00-4281-839a-c65e39e57089",
            "1234",
            "C7542C50DAD532D284F06853FDA10056F65FBC3ED0EF6B519E7CEBDEF7FB25C8D00D86F86D3B7471FE2E75946B677ED4A7414BEA225A06B581516E680D8922CB"
        );
        logger.info(JSON.stringify(encryptParams));


        const endTime = new Date().getTime();
        logger.info(`耗时： ${(endTime - startTime) / 1000} 秒`);
}
)();
