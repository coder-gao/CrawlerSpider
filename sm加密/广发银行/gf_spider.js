const log4js = require('log4js');
const axios = require('axios');
const smcrypto = require('sm-crypto');
// Adding crypto for sha1 encryption
const cryptoJS  = require('crypto-js');

log4js.configure({
    appenders: {
        console: { type: 'console' }
    },
    categories: {
        default: { appenders: ['console', ], level: 'all' }
    }
});

const logger = log4js.getLogger('gf_spider');
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
    static async login()    {

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

        const endTime = new Date().getTime();
        logger.info(`耗时： ${(endTime - startTime) / 1000} 秒`);
}
)();
