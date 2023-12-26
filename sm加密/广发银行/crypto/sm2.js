/*
sm2 v1.1
create by liangruxing
*/
var debug = false;
//国密推荐参数

function SM2(){

    var gm_sm2_ecParams = {
        "p":"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF",
        "a":"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC",
        "b":"28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93",
        "n":"FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
        "gx":"32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7",
        "gy":"BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0",
        "keylen":256
    };

    var private_ecc_p = new BigInteger(gm_sm2_ecParams['p'],16);
    var private_ecc_a= new BigInteger(gm_sm2_ecParams['a'],16);
    var private_ecc_b = new BigInteger(gm_sm2_ecParams['b'],16);
    var private_ecc_n = new BigInteger(gm_sm2_ecParams['n'],16);
    var private_ecc_gx = new BigInteger(gm_sm2_ecParams['gx'],16);
    var private_ecc_gy = new BigInteger(gm_sm2_ecParams['gy'],16);
    var private_rng = new SecureRandom();

    var private_ecCurve = new ECCurveFp(private_ecc_p, private_ecc_a, private_ecc_b);
    var private_ecPointG = ECPointFp.decodeFromHex(private_ecCurve,"04"+gm_sm2_ecParams['gx']+gm_sm2_ecParams['gy']);


    /**
     * 获取随机数
     * @param limit
     * @returns BigInteger大随机数
     */
    function sm2GetBigRandNum(limit) {
        return new BigInteger(limit.bitLength(), private_rng)
            .mod(limit.subtract(BigInteger.ONE))
            .add(BigInteger.ONE)
            ;
    }
    /**
     * 将BigInteger格式化固定长度的字节数组
     * @param bg BigInteger
     * @param needLength 需要的长度
     * @returns 字节数组（并非真正的字节数组，只是数值上是）
     */
    function sm2FormartPointXY(bg,needLength) {

        var tmp = new Array(needLength);
        for(var i = 0;i<tmp.length;i++){
            tmp[i] = 0;
        }
        var bgByte = bg.toByteArray();
        if(bgByte == null) {
            return null;
        }

        if(bgByte.length > needLength) {
            arrayCopy(bgByte, bgByte.length - needLength, tmp, 0, needLength);
        }else if(bgByte.length == needLength) {
            tmp = bgByte;
        }else {
            arrayCopy(bgByte, 0, tmp, needLength - bgByte.length, bgByte.length);
        }

        return tmp;
    }
    /**
     * kdf函数，仅内部使用
     * @param xy
     * @param data
     * @returns {Number}
     */
    function sm2KDF(xy,data) {

        var loop = Math.ceil(data.length/32);
        var sm3;
        var hash = new Array(32);

        for(var i = 0;i<loop;i++) {
            sm3 = new SM3Digest();
            sm3.update(xy,0,xy.length);
            sm3.update(intToByte(i+1),0,4);
            hash = sm3.doFinal();

            for(var  j = 0;j<hash.length&&(i*32+j)<data.length;j++) {
                data[i*32+j] ^= hash[j];
            }
        }

        return 0;
    }

    /**
     * 生成sm2公私钥对
     * @returns 返回json格式、BigInteger类型的公私钥：{'privkey': biPrv, "pubkey":epPub}
     */
    function sm2GenKeyPair(){
        var biN = private_ecc_n;
        var biPrv = null;
        var epPub = null;
        while(true){
            do
            {
                biPrv = sm2GetBigRandNum(biN);
            }
            while (biPrv.equals(BigInteger.ZERO) || biPrv.compareTo(biN) >= 0 || biPrv.bitLength() < 249);

            epPub = private_ecPointG.multiply(biPrv);
            if(epPub.getX().toBigInteger().bitLength() >= 249 && epPub.getY().toBigInteger().bitLength() >= 249){

                break;
            }
        }
        return {'privkey': biPrv, "pubkey":epPub};
    }

    /**
     * 生成sm2公私钥对
     * @returns json格式、hex编码的密钥对：{'privkeyhex': priv, 'pubkeyhex': pub}
     */
    function sm2GenKeyPairHex(){
        var key = sm2GenKeyPair();
        var biX = key['pubkey'].getX().toBigInteger();
        var biY = key['pubkey'].getY().toBigInteger();

        var charlen = gm_sm2_ecParams['keylen'] / 4;
        var hPrv = ("0000000000" + key['privkey'].toString(16)).slice(- charlen);
        var hX   = ("0000000000" + biX.toString(16)).slice(- charlen);
        var hY   = ("0000000000" + biY.toString(16)).slice(- charlen);
        var hPub = "04" + hX + hY;

        return {'privkeyhex': hPrv, 'pubkeyhex': hPub};
    }

    /**
     * 比较字节数组是否一致
     * @param src1 数组
     * @param pos1 开始位置
     * @param src2 数组
     * @param pos2 开始位置
     * @param len 比较的长度
     * @returns 返回0，则表示一致，返回-1表示不一致
     */
    function sm2ArrayCompare(src1,pos1,src2,pos2,len) {

        if(src1.length - pos1 < len) {
            return -1;
        }
        if(src2.length - pos2 < len) {
            return -1;
        }
        for(var i = 0;i<len;i++) {
            if(src1[pos1++] != src2[pos2++]) {
                return -1;
            }
        }

        return 0;
    }
    /**
     * sm2加密
     * @param pubkey hex编码的公钥
     * @param dataHex 待加密的数据，hex编码
     * @returns 密文数据，hex编码
     */
    function sm2Encrypt(pubkey,dataHex){
        var cipher;

        if(pubkey == null || pubkey.length == 0 || dataHex == null || dataHex.length == 0) {
            return null;
        }

        if(pubkey.length == 128) {
            pubkey = "04"+pubkey;
        }

        var data = Hex.decode(dataHex);
        var userKey = ECPointFp.decodeFromHex(private_ecCurve,pubkey);
        var c2 = null;
        var c1 = null;
        var x2 = null;
        var y2 = null;
        var loop = 0;
        do{
            var kp = sm2GenKeyPair();
            if(debug == true){
                console.log("priv"+kp['privkey'].toString(16));
                console.log("x1="+kp['pubkey'].getX().toBigInteger().toString(16));
                console.log("y1="+kp['pubkey'].getY().toBigInteger().toString(16));
            }
            c1 = kp['pubkey'];


            var x2y2 = userKey.multiply(kp['privkey']);
            x2 = sm2FormartPointXY(x2y2.getX().toBigInteger(), 32);
            y2 = sm2FormartPointXY(x2y2.getY().toBigInteger(), 32);

            c2 = new Array(data.length);
            arrayCopy(data,0,c2,0,data.length);
            var xy = new Array(x2.length+y2.length);
            arrayCopy(x2, 0, xy, 0, x2.length);
            arrayCopy(y2, 0, xy, x2.length, y2.length);
            sm2KDF(xy, c2);

            loop++;

        }while(sm2ArrayCompare(c2,0,data,0,data.length) == 0 && loop < 10);
        if(loop >= 10){
            //失败次数过多，直接返回
            console.log("加密失败！失败次数："+loop);
            return null;
        }

        var sm3 = new SM3Digest();
        sm3.update(x2,0,x2.length);
        sm3.update(data,0,data.length);
        sm3.update(y2,0,y2.length);
        var c3 = sm3.doFinal();

        var c1x = c1.getX().toBigInteger().toByteArray();
        var c1y = c1.getY().toBigInteger().toByteArray();

        var cipher = sm2CipherToDer(c1x,c1y,c2,c3);
        if((c1x.length == 32 && c1x[0] == 0) || (c1y.length == 32 && c1y[0] == 0)){
            console.log("cipher:"+Hex.encode(cipher,0,cipher.length));
        }
        return Hex.encode(cipher,0,cipher.length);
    }
    /**
     * sm2解密
     * @param privkey 私钥，hex编码
     * @param cipherHex 密文，hex编码，der格式
     * @returns 返回明文数据，hex编码
     */
    function sm2Decrypt(privkey,cipherHex) {
        var cipher = Hex.decode(cipherHex);
        var dec = sm2DerDecode(cipher);

        var c1 = new Array(64+1);
        var c2 = new Array(dec["c2"].length);
        var c3 = new Array(32);

        arrayCopy(dec["c1x"], dec["c1x"].length-32, c1, 1, 32);
        arrayCopy(dec["c1y"], dec["c1y"].length-32, c1, 1+32, 32);
        c1[0] = 0x04;
        var c1Point = ECPointFp.decodeFromHex(private_ecCurve,Hex.encode(c1,0,c1.length));

        var x2y2Point = c1Point.multiply(new BigInteger(privkey,16));
        var x2 = sm2FormartPointXY(x2y2Point.getX().toBigInteger(), 32);
        var y2 = sm2FormartPointXY(x2y2Point.getY().toBigInteger(), 32);
        var xy = new Array(x2.length+y2.length);
        arrayCopy(x2, 0, xy, 0, x2.length);
        arrayCopy(y2, 0, xy, x2.length, y2.length);

        arrayCopy(dec["c2"], 0, c2, 0, c2.length);
        var c2Copy = new Array(c2.length);
        arrayCopy(c2, 0, c2Copy, 0, c2.length);
        sm2KDF(xy, c2);
        if(sm2ArrayCompare(c2Copy,0,c2,0,c2.length) == 0){
            console.log("kdf is all 0");
            return null;
        }

        var sm3 = new SM3Digest();
        var hash = new Array(32);
        sm3.update(x2,0,x2.length);
        sm3.update(c2,0,c2.length);
        sm3.update(y2,0,y2.length);
        hash = sm3.doFinal();

        if(sm2ArrayCompare(hash, 0, dec["c3"], 0, 32) != 0) {
            return null;
        }


        return Hex.encode(c2,0,c2.length);
    }
    /**
     * 将密文编码成der格式
     * @param c1x
     * @param c1y
     * @param c2
     * @param c3
     * @returns {Array}
     */
    function sm2CipherToDer(c1x,c1y,c2,c3){
        var c2Len = c2.length;
        var c2Tag = [];
        if(c2Len < 0x80){
            c2Tag[0] = 0x04;
            c2Tag[1] = c2Len;
        }else{
            c2Tag[0] = 0x04;
            var c2LenBytes = intToByte(c2Len);
            var i = 0;
            while(c2LenBytes[i] == 0 && i < c2LenBytes.length){
                i++;
            }
            c2Tag[1] = 0x80 | (c2LenBytes.length - i);
            for(var j = 2;i<c2LenBytes.length;i++,j++){
                c2Tag[j] = c2LenBytes[i];
            }
        }
        var totalTagLen = c1x.length+c1y.length+c2.length+c3.length+6+c2Tag.length;
        var totalTag = [];
        totalTag[0] = 0x30;
        if(totalTagLen < 0x80){
            totalTag[1] = totalTagLen;
        }else{
            var totalTagLenBytes = intToByte(totalTagLen);
            var i = 0;
            while(totalTagLenBytes[i] == 0 && i < totalTagLenBytes.length){
                i++;
            }
            totalTag[1] = 0x80 | (totalTagLenBytes.length - i);
            for(var j = 2;i<totalTagLenBytes.length;i++,j++){
                totalTag[j] = totalTagLenBytes[i];
            }
        }

        var der = new Array(totalTagLen+totalTag.length);
        var derLen = 0;

        arrayCopy(totalTag, 0, der, 0, totalTag.length);
        derLen += totalTag.length;

        der[derLen++] = 0x02;
        der[derLen++] = c1x.length;
        arrayCopy(c1x, 0, der, derLen, c1x.length);
        derLen += c1x.length;

        der[derLen++] = 0x02;
        der[derLen++] = c1y.length;
        arrayCopy(c1y, 0, der, derLen, c1y.length);
        derLen += c1y.length;

        der[derLen++] = 0x04;
        der[derLen++] = c3.length;
        arrayCopy(c3, 0, der, derLen, c3.length);
        derLen += c3.length;

        arrayCopy(c2Tag, 0, der, derLen, c2Tag.length);
        derLen += c2Tag.length;
        arrayCopy(c2, 0, der, derLen, c2.length);

        return der;
    }
    /**
     * 将der格式密文解码
     * @param der
     * @returns
     */
    function sm2DerDecode(der){
        var pos = 0;
        var totalLen = 0;

        if(der[pos++] != 0x30){
            return null;
        }
        if((der[pos] & 0xFF) <= 0x7F){
//			totalLen = der[pos++] & 0xFF;
            pos++;
        }else{
            pos += (der[pos] & 0x7F)+1;
        }

        pos++;
        var c1xLen = der[pos];
        var c1x = new Array(32);
        for(var i = 0;i<c1x.length;i++){
            c1x[i] = 0;
        }
        if(c1xLen <= 32){
            arrayCopy(der, ++pos , c1x, 32-c1xLen, c1xLen);
        }else{
            arrayCopy(der, ++pos+(c1xLen-32) , c1x, 0, 32);
        }
        pos += c1xLen;

        pos++;
        var c1yLen = der[pos];
        var c1y = new Array(32);
        for(var i = 0;i<c1y.length;i++){
            c1y[i] = 0;
        }
        if(c1yLen <= 32){
            arrayCopy(der, ++pos , c1y, 32-c1yLen, c1yLen);
        }else{
            arrayCopy(der, ++pos+(c1yLen-32) , c1y, 0, 32);
        }
        pos += c1yLen;

        pos++;
        var c3Len = der[pos];
        var c3 = new Array(c3Len);
        arrayCopy(der, ++pos , c3, 0, c3Len);
        pos += c3Len;

        pos++;
        var c2Len = 0;
        if((der[pos] & 0xFF) <= 0x7F){
            c2Len = der[pos] & 0xFF;
        }else{
            for(var i = 0,j = (der[pos] & 0x7F)-1;i<(der[pos] & 0x7F);i++,j--){
                c2Len = c2Len | ((der[pos+i+1]&0xFF) << (j*8)) ;
            }
            pos += (der[pos] & 0x7F);
        }
        var c2 = new Array(c2Len);
        arrayCopy(der, ++pos , c2, 0, c2Len);
        pos += c2Len;

        return {'c1x': c1x, "c1y":c1y,"c2":c2,"c3":c3};
    }
    function sm2CipherToC1C3C2(der){
        var cipherBinary = Hex.decode(der);
        var dec = sm2DerDecode(cipherBinary);

        var c1c3c2 = new Array(dec["c1x"].length+dec["c1y"].length+dec["c2"].length+dec["c3"].length);

        var pos = 0;
        arrayCopy(dec["c1x"], 0, c1c3c2, pos, dec["c1x"].length);
        pos += dec["c1x"].length;
        arrayCopy(dec["c1y"], 0, c1c3c2, pos, dec["c1y"].length);
        pos += dec["c1y"].length;
        arrayCopy(dec["c3"], 0, c1c3c2, pos, dec["c3"].length);
        pos += dec["c3"].length;
        arrayCopy(dec["c2"], 0, c1c3c2, pos, dec["c2"].length);

        return Hex.encode(c1c3c2,0,c1c3c2.length);
    }

    //对外提供的接口
    this.genKeyPair = sm2GenKeyPair;
    this.genKeyPairHex = sm2GenKeyPairHex;
    this.encrypt = sm2Encrypt;
    this.decrypt = sm2Decrypt;
    this.cipherToDer = sm2CipherToDer;
    this.derDecode = sm2DerDecode;
    this.cipherToC1C3C2 = sm2CipherToC1C3C2;
}

export default SM2;
