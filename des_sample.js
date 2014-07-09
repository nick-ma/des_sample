var assert = require('assert');
var crypto = require('crypto');

function test_des(param) {
    var key = new Buffer(param.key);
    var iv = new Buffer(param.iv ? param.iv : 0)
    var plaintext = param.plaintext
    var alg = param.alg
    var autoPad = param.autoPad

    //encrypt
    var cipher = crypto.createCipheriv(alg, key, iv);
    cipher.setAutoPadding(autoPad) //default true
    var ciph = cipher.update(plaintext, 'utf8', 'hex');
    ciph += cipher.final('hex');
    // console.log(alg, ciph)

    //decrypt
    var decipher = crypto.createDecipheriv(alg, key, iv);
    cipher.setAutoPadding(autoPad)
    var txt = decipher.update(ciph, 'hex', 'utf8');
    txt += decipher.final('utf8');
    assert.equal(txt, plaintext, 'fail');
    console.log('算法:', alg, '原文:', plaintext, '加密:', ciph, '解密:', txt);
}

// do test

test_des({
    alg: 'des-ecb',
    autoPad: true,
    key: '01234567',
    plaintext: '99999999',
    iv: null
})

test_des({
    alg: 'des-cbc',
    autoPad: true,
    key: '12345678',
    plaintext: '99999999',
    iv: '12345678'
})

test_des({
    alg: 'des-ede3', //3des-ecb
    autoPad: true,
    key: '0123456789abcd0123456789',
    plaintext: '99999999',
    iv: null
})

test_des({
    alg: 'des-ede3-cbc', //3des-cbc
    autoPad: true,
    key: '12345678901234567890abcd',
    plaintext: '99999999',
    iv: '12345678'
})