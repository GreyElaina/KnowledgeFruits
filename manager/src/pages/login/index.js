import Vue from 'vue'
import ElementUI from 'element-ui';
import 'element-ui/lib/theme-chalk/index.css';
import Login from "./login.vue"
import VueCookies from "vue-cookies"

Vue.use(ElementUI)
Vue.use(VueCookies)

var app = new Vue({
    el: "#app",
    data(){
        return {}
    },
    render: h => h(Login)
})