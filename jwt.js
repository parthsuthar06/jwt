//@ts-check
'use strict';
const jwt = require('jsonwebtoken')
    , fs = require('fs');
/**
 * Case 1: 'SH256'
 */
const SECRET = 'mysecret'
/**
 * Case 2: 'RS256' -> Required public private key pair
 * generated : https://qsandbox.com/tools/private-public-keygen
 * and format above key using below linux cmd:
 * 'openssl rsa -in private_key_filename -pubout -outform PEM -out public_key_output_filename'
 */
const PUBLICKEY = fs.readFileSync('./public.key', 'utf8') //for other ms validating token
    , PRIVATEKEY = fs.readFileSync('./private.key', 'utf8'); // for AuthN server-side

/**
 * Signed -> covered both the cases;
 * incase of 'RS256' this below fn should be at server side
 */
const signToken = (payload, privateKey) => {
    if (privateKey)
        return jwt.sign(payload, privateKey, { algorithm: 'RS256' })
    return jwt.sign({ data: JSON.stringify(payload) }, SECRET) //default algo 'SH256'
}
/**
 * incase of 'RS256' below fn can be client and 
 * then they directy verify using public key token
 * eg: authN ms for generating (signed) token and other ms 
 * will use public to verify signed token so this will reduce
 * unneccesary calls to Authenticate ms verify token.
 */
const verify = (token, publicKey) => {
    if (publicKey)
        return jwt.verify(token, publicKey, { algorithms: ['RS256'] })
    return jwt.verify(token, SECRET)
}

//main fn
(async () => {
    try {
        //AuthN ms calls
        const payload = { foo: 'bar' };
        console.log('payload--->', payload)
        const token = signToken(payload, PRIVATEKEY)
        console.log('token--->', token)
        //client side ms calls
        const decode = verify(token, PUBLICKEY);
        console.log('decode--->', decode); //use decode value to process futher like acl
    } catch (e) {
        console.log('err--->', e)
    }
})()
/**
 * helper fn 
 */
function encodeToBase64(rawString) {
    const buffer = new Buffer(rawString)
    return buffer.toString('base64')
}

function decodeToAscii(encodedString) {
    const buffer = new Buffer(encodedString, 'base64')
    return buffer.toString('ascii')
}
