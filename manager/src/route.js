import VueRouter from 'vue-router'
import TemplateLogin from './authenticate/login.vue'


export default new VueRouter({
    routes: [
        {path: "/authenticate/login", components: TemplateLogin}
    ]
})