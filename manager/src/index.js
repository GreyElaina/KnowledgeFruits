import Vue from 'vue'
import ElementUI from 'element-ui';
import 'element-ui/lib/theme-chalk/index.css';
import App from "./app.vue"
import VueCookies from "vue-cookies"

Vue.use(ElementUI)
Vue.use(VueCookies)

var app = new Vue({
    el: "#app",
    data(){
        return {}
    },
    render: h => h(App)
})