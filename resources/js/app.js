// Javascript dependences and CSRF token
require('./bootstrap');
// Vue dependences
import Vue from 'vue';
import VueRouter from 'vue-router';
import VueAxios from 'vue-axios';
import ElementUI from 'element-ui';
import lang from 'element-ui/lib/locale/lang/es';
import locale from 'element-ui/lib/locale';
import 'element-ui/lib/theme-chalk/index.css';

locale.use(lang);
Vue.use(ElementUI);
Vue.use(VueRouter);
Vue.use(VueAxios, window.axios);

import routes from './routes/routes';
Vue.router = new VueRouter({
  routes
});

Vue.use(require('@websanova/vue-auth'), {
  auth: require('@websanova/vue-auth/drivers/auth/bearer.js'),
  http: require('@websanova/vue-auth/drivers/http/axios.1.x.js'),
  router: require('@websanova/vue-auth/drivers/router/vue-router.2.x.js'),
  rolesVar: 'type',
  loginData: { url: '/login' },
  logoutData: { url: '/logout' },
  fetchData: { url: '/api/user' },
  refreshData: { enabled: false },
  rolesVar: 'role',
});

let VueStore = require('@websanova/vue-store');
Vue.use(VueStore);

// Initialize Vue

let component = require('./views/App.vue');
component.router = Vue.router;
new Vue(component).$mount('#app');
