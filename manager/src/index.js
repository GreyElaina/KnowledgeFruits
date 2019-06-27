import Vue from 'vue'
import ElementUI from 'element-ui';
import 'element-ui/lib/theme-chalk/index.css';
import App from "./app.vue"

Vue.use(ElementUI)

var app = new Vue({
    el: "#app",
    data(){
        return {}
    },
    render: h => h(App)
})