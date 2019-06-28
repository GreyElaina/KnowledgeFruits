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
            <strong>登录</strong>
          </div>
          <el-input placeholder="邮箱地址" suffix-icon="el-icon-user" v-model="email" clearable></el-input>
          <el-input placeholder="密码" show-password style="margin-top:4px;" v-model="password"></el-input>
          <el-divider></el-divider>
          <el-button
            type="primary"
            :loading="loading_loginbuttom"
            style="width:100%;position:relative"
            @click="verify"
          >登录</el-button>
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
import RotateButtomComponent from "../../composents/rotatebuttom.vue";
import axios from "axios";
import config from "../../config.js";
import { sha256 } from "js-sha256";

export default {
  data() {
    return {
      email: "",
      password: "",
      failed_email: "",
      loading_loginbuttom: false
    };
  },
  components: {
    rotateButtom: RotateButtomComponent
  },
  methods: {
    verify() {
      var that = this;
      this.loading_loginbuttom = true;
      if (
        !/^([a-zA-Z0-9]+[_|\_|\.]?)*[a-zA-Z0-9]+@([a-zA-Z0-9]+[_|\_|\.]?)*[a-zA-Z0-9]+\.[a-zA-Z]{2,3}$/.test(
          this.email
        )
      ) {
        this.$notify.error({
          title: "填写错误",
          message: "邮箱填写错误"
        });
        this.loading_loginbuttom = false;
        return false;
      }
      axios
        .post(
          `${config.source}/api/knowledgefruits/authenticate/security/signin`,
          {
            username: this.email,
            authid: Math.random()
              .toString(36)
              .substring(2)
          }
        )
        .then(function(response) {
          axios
            .post(
              `${
                config.source
              }/api/knowledgefruits/authenticate/security/verify`,
              {
                authId: response.data.authId,
                Password: sha256(
                  sha256(that.password + response.data.salt) +
                    response.data.HashKey
                ),
                requestUser: true
              }
            )
            .then(function(response) {
              that.$cookies.set("accessToken", response.data.accessToken);
              that.$cookies.set("clientToken", response.data.clientToken);
              that.$cookies.set("userId", response.data.metadata.user.userId);
              that.$notify({
                title: "登录成功",
                message: "我们将马上为您跳转到面板主页...",
                type: "success"
              });
            })
            .catch(function(e) {
              that.loading_loginbuttom = false;
              that.$notify.error({
                title: "验证错误",
                message: "密码错误,请重新输入."
              });
            });
        })
        .catch(function(e) {
          that.$notify.error({
            title: "填写错误",
            message: "邮箱填写错误, 你还没有注册."
          });
          that.loading_loginbuttom = false;

          throw e;
        });
    }
  }
};
</script>