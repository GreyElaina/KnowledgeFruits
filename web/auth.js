const vue = require('vue');
const crypto = require('crypto-js');
const axios = require('axios');
const config = require('./config.js')

const BaseUrl = () => {
    axios.get(config.BaseUrl + "/api/knowledgefruits/").then((response) => {
        return config.BaseUrl + response.json['Yggdrasil']['BaseUrl'];
    }).catch((err) => {
        throw err;
    });
};

const getPublicKey = () => {
    axios.get(BaseUrl()).then((response) => {
        return response.json['signaturePublickey'];
    });
};

const CryptWithPublicKey = (Message, PublicKey=getPublicKey()) => {
    return crypto.publicEncrypt(PublicKey, Buffer.from(Message)).toString("base64");
};

const crypt = (Message, Salt) => {
    return crypto.SHA256(Message + Salt);
};

const auth = function(email=document.getElementById("email").value, password=document.getElementById("passwd").value){
    let IReturn = {};
    axios.post(config.BaseUrl + "/api/knowledgefruits/login/randomkey", {
        "username": email
    }).then(function(response){
        let data = response.data;
        let authId = data['authId'];
        let HashKey = data['HashKey'];
        let salt = data['salt'];
        let crypted = crypt(crypt(password, salt), HashKey);
        
        axios.post(config.BaseUrl + "/api/knowledgefruits/login/randomkey/verify", {
            "authId": authId,
            "Password": crypted.toString()
        }).then((response1) => {
            IReturn = response1;
        }).catch((err) => {
            throw err;
        });
    }).catch((err) => {
        throw err;
    });
    return IReturn ;
};

//document.getElementById("button_sign").addEventListener('click', auth, false);
console.log(auth(email='1846913566@qq.com', password='asd123456').then((res)=> console.log(res)));