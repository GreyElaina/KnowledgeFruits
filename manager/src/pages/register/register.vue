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
          axios
            .post(`${config.source}/api/knowledgefruits/register/`, {
              email: that.email,
              password: that.encrypt(
                response.data.Yggdrasil.info.signaturePublickey,
                that.password
              ),
              username: that.username
            })
            .then(function(response) {
              that.$notify({
                title: "提交请求成功",
                message: "请于你所填写的邮箱内收取我们发送的验证邮件",
                type: "success"
              });
            })
            .catch(function(e) {
              switch (e.response.data.errorMessage) {
                case "Access token already has a profile assigned.":
                  that.$notify.error({
                    title: "提交请求失败",
                    message: "邮箱地址未符合后端规范."
                  });
                  break;
                case "Invalid token.":
                  that.$notify.error({
                    title: "提交请求失败",
                    message: "所填写的密码未符合后端规范."
                  });
                  break;
                case "Invalid credentials. Invalid username or password.":
                  that.$notify.error({
                    title: "提交请求失败",
                    message: "所填写的昵称未符合后端规范."
                  });
                  break;
                case "Duplicate data.":
                  that.$notify.error({
                    title: "提交请求失败",
                    message: "你已经注册过了."
                  });
                  break;
                case "Frequency limit, wait a moment.":
                  that.$notify.error({
                    title: "提交请求失败",
                    message: "请不要重复发送请求,3分钟后再试,该次请求后生效."
                  });
                  break;
              }
            });
        });
    }
  }
};
</script>
