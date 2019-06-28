<template>
  <div style="position:relative;width:100%;height:100%;flex-direction:column;display:flex">
    <!--<rotate-buttom :hasIcon="true" iconClass="el-icon-arrow-down el-icon--right">旋转吧箭头</rotate-buttom>-->
    <el-header></el-header>
    <div
      style="position:absolute;margin:0 auto;margin-top:96px;width:329px;height:192px;align-self:center;"
    >
      <div>
        <el-card>
          <div slot="header" class="clearfix" style="text-align:center;">
            <strong>注册</strong>
          </div>
          <el-input placeholder="邮箱地址" suffix-icon="el-icon-user" v-model="email" clearable></el-input>
          <el-input placeholder="昵称" style="margin-top:4px;" v-model="username"></el-input>
          <el-input placeholder="密码" show-password style="margin-top:4px;" v-model="password"></el-input>
          <el-divider></el-divider>
          <el-button
            type="primary"
            :loading="loading_loginbuttom"
            style="width:100%;position:relative"
            @click="verify"
          >注册</el-button>
        </el-card>
      </div>
    </div>
  </div>
</template>

<style>
.clearfix:before,
.clearfix:after {
  display: table;
  content: "";
}
.clearfix:after {
  clear: both;
}
</style>
<script>
import axios from "axios";
import JSEncrypt from "jsencrypt";
import config from "../../config.js";

export default {
  data() {
    return {
      email: "",
      username: "",
      password: "",
      loading_loginbuttom: false
    };
  },
  methods: {
    encrypt(publicKey, password) {
      var en = new JSEncrypt();
      en.setPublicKey(publicKey);
      return en.encrypt(password);
    },
    verify() {
      let that = this;
      axios
        .get(`${config.source}/api/knowledgefruits`)
        .then(function(response) {
          axios.post(`${config.source}/api/email/verify`, {
              password: that.encrypt(response.data.Yggdrasil.info.signaturePublickey, that.password),
              verify: that.password
          });
        });
    }
  }
};
</script>
