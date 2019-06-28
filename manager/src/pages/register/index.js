import Vue from 'vue'
import ElementUI from 'element-ui';
import 'element-ui/lib/theme-chalk/index.css';
import Register from "./register.vue"
import jsEncrypt from "jsencrypt"

Vue.use(ElementUI)
Vue.prototype.jsEncrypt = jsEncrypt

var app = new Vue({
    el: "#app",
    data(){
        return {}
    },
    render: h => h(Register)
})