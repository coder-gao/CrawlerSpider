/*
sm3 v1.1
create by liangruxing
*/


//500M以上数据不能加密

function SM3Digest(){

    var private_ivByte = new Array( 0x73,  0x80, 0x16, 0x6f, 0x49,
        0x14,  0xb2, 0xb9, 0x17, 0x24, 0x42, 0xd7,
        0xda,  0x8a, 0x06, 0x00, 0xa9, 0x6f, 0x30,
        0xbc,  0x16, 0x31, 0x38, 0xaa, 0xe3,
        0x8d,  0xee, 0x4d, 0xb0, 0xfb, 0x0e,
        0x4e );
    var private_iv = byteArrayToIntArray(
        private_ivByte
    );
    var private_tj = new Array(64);
    var BLOCK_BYTE_LEN = 64;

    var private_vbuf = new Array(8);

    var private_dataBuf = new Array(64);

    var private_dataBufLen = 0;

    var private_totalLen = 0;//TODO 需要long

    for(var i = 0;i<64;i++) {
        if(i<=15) {
            private_tj[i] = 0x79cc4519;
        }else {
            private_tj[i] = 0x7a879d8a;
        }
    }
    arrayCopy(private_iv, 0, private_vbuf, 0, private_vbuf.length);

    function ffj(x,y,z,i){
        var tmp;
        if(i<=15) {
            tmp = x^y^z;
        }else{
            tmp = (x&y)|(x&z)|(y&z);
        }

        return tmp;
    }
    function ggj(x,y,z,i){
        var tmp = 0;
        if(i<=15) {
            tmp = x^y^z;
        }else {
            tmp = (x&y)|(~x&z);
        }

        return tmp;
    }
    function p0(x) {
        return x^(x<<9|(x>>>(32-9)))^(x<<17|(x>>>(32-17)));
    }
    function p1(x) {
        return x^(x<<15|(x>>>(32-15)))^(x<<23|(x>>>(32-23)));
    }

    function cycleLeft(x,moveLen) {
        return x<<moveLen|(x>>>(32-moveLen));
    }


    function padding(data) {
        var k = 0;
        var len = data.length;
        var padding;

        k = 64 - (len + 1 + 8)%64;
        if(k>=64) {
            k = 0;
        }
        padding = new Array(k+1+len+8);
        padding[len] = 1<<7;


        arrayCopy(data, 0, padding, 0, len);
        arrayCopy(longToByte(private_totalLen<<3), 0, padding, len+k+1, 8);

        return padding;
    }

    function iterate(message) {
        var len = message.length;
        var n = parseInt(len/16);
        var v,b;
        var ep;

        v = private_vbuf;
        b = new Array(16);

        for(var i = 0;i<n;i++) {
            arrayCopy(message, i*16, b, 0, b.length);
            ep = expand(b);
            v = cf(v, ep[0], ep[1]);
        }
        arrayCopy(v, 0, private_vbuf, 0, v.length);
    }

    function expand(b) {
        var w1 = new Array(68);
        var w2 = new Array(64);

        arrayCopy(b, 0, w1, 0, b.length);

        for(var i = 16;i<w1.length;i++) {
            w1[i] = p1(w1[i-16]^w1[i-9]^cycleLeft(w1[i-3], 15))^cycleLeft(w1[i-13],7)^w1[i-6];
        }

        for(var i = 0;i<w2.length;i++) {
            w2[i] = w1[i]^w1[i+4];
        }

        return new Array(w1,w2);
    }

    function cf(v,w1,w2) {
        var result;
        var a,b,c,d,e,f,g,h,ss1,ss2,tt1,tt2;
        a = v[0];
        b = v[1];
        c = v[2];
        d = v[3];
        e = v[4];
        f = v[5];
        g = v[6];
        h = v[7];

        for(var i = 0;i<64;i++) {
            ss1 = cycleLeft(cycleLeft(a, 12)+e+cycleLeft(private_tj[i], i),7);
            ss2 = ss1^cycleLeft(a, 12);
            tt1 = ffj(a, b, c,i)+d+ss2+w2[i];
            tt2 = ggj(e,f,g,i)+h+ss1+w1[i];
            d = c;
            c = cycleLeft(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = cycleLeft(f, 19);
            f = e;
            e = p0(tt2);
        }

        result = new Array(8);
        result[0] = a^v[0];
        result[1] = b^v[1];
        result[2] = c^v[2];
        result[3] = d^v[3];
        result[4] = e^v[4];
        result[5] = f^v[5];
        result[6] = g^v[6];
        result[7] = h^v[7];


        return result;
    }

    /**
     * 计算mac值
     * @param data
     * @returns
     */
    function sm3Digest(data) {
        var mac;

        var padding = padding(data);
        var paddingInt = byteArrayToIntArray(padding);
        iterate(paddingInt);
        var macInt = private_vbuf;
        mac = intArrayToByteArray(macInt);
        return mac;
    }

    /**
     * 添加需要计算sm3值的数据，可分多次添加
     * @param data 需要计算sm3值的数据
     * @param pos 开始位置
     * @param len 长度
     */
    function sm3Update(data,pos,len) {

        var loop = parseInt((len+private_dataBufLen)/64);
        private_totalLen += len;

        if(len+private_dataBufLen<BLOCK_BYTE_LEN) {
            arrayCopy(data, 0, private_dataBuf, private_dataBufLen, len);
            private_dataBufLen = len+private_dataBufLen;
        }else {
            var dataInt;
            arrayCopy(data, 0 , private_dataBuf, private_dataBufLen, BLOCK_BYTE_LEN-private_dataBufLen);
            dataInt = byteArrayToIntArray(private_dataBuf);
            iterate(dataInt);
            for(var i = 1;i<loop;i++) {
                arrayCopy(data, i*BLOCK_BYTE_LEN-private_dataBufLen, private_dataBuf, 0, BLOCK_BYTE_LEN);
                dataInt = byteArrayToIntArray(private_dataBuf);
                iterate(dataInt);
            }
            arrayCopy(data, loop*BLOCK_BYTE_LEN-private_dataBufLen , private_dataBuf, 0, len-(loop*BLOCK_BYTE_LEN-private_dataBufLen));
            private_dataBufLen = len-(loop*BLOCK_BYTE_LEN-private_dataBufLen);
        }

    }
    /**
     * 获取最终的sm3值
     * @returns 返回sm3值，字节数据
     */
    function sm3DoFinal() {
        var mac;
        var finalData = new Array(private_dataBufLen);

        arrayCopy(private_dataBuf, 0, finalData, 0, private_dataBufLen);

        var paddingArr = padding(finalData);
        var paddingInt = byteArrayToIntArray(paddingArr);
        iterate(paddingInt);
        var macInt = private_vbuf;
        mac = intArrayToByteArray(macInt);
        return mac;

    }

    //对外提供的接口
    this.digest = sm3Digest;
    this.update = sm3Update;
    this.doFinal = sm3DoFinal;

}

export default SM3Digest;
