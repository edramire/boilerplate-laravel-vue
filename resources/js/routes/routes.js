import NotFound from '../views/404.vue';
import Home from '../views/layouts/Home.vue';
import Login from '../views/Login.vue';
import adminRoutes from '../routes/admin-routes';
import publicRoutes from '../routes/public-routes';

export default [{
  path: '/login',
  component: Login,
  name: 'Login',
  hidden: true,
  meta: { auth: false }
},{
  path: '/',
  component: Home,
  name: 'Home',
  children: [].concat(adminRoutes).concat(publicRoutes),
  redirect: {name: 'Administración'}
},{
  path: '/404',
  component: NotFound,
  name: '',
  hidden: true
},{
  path: '*',
  hidden: true,
  redirect: { path: '/404' }
}];
