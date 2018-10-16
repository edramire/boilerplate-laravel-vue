import Administracion from '../views/admin/Home.vue';

import IndexUsuario from '../views/admin/usuarios/Index.vue';
import CrearUsuario from '../views/admin/usuarios/Crear.vue';
import EditarUsuario from '../views/admin/usuarios/Editar.vue';

import IndexRoles from '../views/admin/roles/Index.vue';
import CrearRoles from '../views/admin/roles/Crear.vue';
import EditarRoles from '../views/admin/roles/Editar.vue';

export default [{
  path: 'admin/',
  name: 'Administracion',
  component: Administracion,
  meta: {
    auth: 'admin',
  },
  redirect: {name: 'Usuarios'},
  children: [
    {
      path: 'usuarios',
      name: 'AdminUsuario',
      component: { template: '<router-view></router-view>' },
      redirect: {name: 'IndexUsuario'},
      children: [
        {
          path: '',
          name: 'IndexUsuario',
          component: IndexUsuario,
        },{
          path: 'crear',
          name: 'CrearUsuario',
          component: CrearUsuario,
        },{
          path: 'editar/:id',
          name: 'EditarUsuario',
          component: EditarUsuario,
        },
      ],
    },
    {
      path: 'roles',
      name: 'AdminRoles',
      component: { template: '<router-view></router-view>' },
      redirect: {name: 'IndexRoles'},
      children: [
        {
          path: '',
          name: 'IndexRoles',
          component: IndexRoles,
        },{
          path: 'crear',
          name: 'CrearRoles',
          component: CrearRoles,
        },{
          path: 'editar/:id',
          name: 'EditarRoles',
          component: EditarRoles,
        },
      ],
    },
  ]
}];
