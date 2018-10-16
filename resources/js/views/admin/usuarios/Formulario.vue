<template>
  <formulario-base>
    <template slot="header">
      <el-col :span="20">
        <h2>{{operacion}} usuarios</h2>
      </el-col>
      <el-col :span="4">
        <router-link :to="{name: 'IndexUsuario'}">
          <el-button type="primary">Atrás</el-button>
        </router-link>
      </el-col>
    </template>

    <template slot="body">
      <el-form ref="form" :model="user" :rules="validation" label-width="200px">
        <el-form-item label="Nombre" prop="name">
          <el-input v-model="user.name" :error="errors.get('name')"></el-input>
        </el-form-item>
        <el-form-item label="Email" prop="email">
          <el-input v-model="user.email" :error="errors.get('email')"></el-input>
        </el-form-item>
        <el-form-item label="Contraseña" prop="password">
          <el-input type="password" v-model="user.password" :error="errors.get('password')"></el-input>
        </el-form-item>
        <el-form-item label="Confirmar contraseña" prop="password_confirmation">
          <el-input type="password" v-model="user.password_confirmation" :error="errors.get('password_confirmation')"></el-input>
        </el-form-item>
        <el-form-item label="Rol">
          <el-select v-model="user.role_id" filterable placeholder="Seleccione rol de usuario" :error="errors.get('role_id')">
            <el-option v-for="(rol) in roles" :label="rol.guard_name" :value="rol.id" :key="rol.id">
            </el-option>
          </el-select>
        </el-form-item>
      </el-form>
    </template>

    <template slot="footer">
      <el-button type="primary" @click.native="submitForm" :loading="loading" icon="fa fa-sign-in">{{operacion}}</el-button>
    </template>
  </formulario-base>
</template>

<script>
import FormularioBase from '../AdminFormularioBase.vue';
import UsersResources from '../../../endpoints/users';
import RolesResources from '../../../endpoints/roles';
import Errors from '../../../common/Errors';

export default {
  components: {
    formularioBase: FormularioBase
  },
  props: ['operacion', 'user'],
  data() {
    return {
      loading: false,
      roles: [],
      establecimientos: [],
      errors: new Errors(),
      servicios: [],
      validation: {
        name: [
          { required: true, message: 'Ingrese nombre de usuario', trigger: 'change' },
        ],
        email: [
          { type: 'email', required: true, message: 'Ingrese un correo electrónico válido', trigger: 'change' }
        ]
      }
    }
  },
  methods: {
    loadRoles() {
      return RolesResources.list().then((res) => {
        this.roles = res.data.data;
      })
    },
    loadEstablecimientos() {
      return EstablecimientosResources.all().then((res) => {
        this.establecimientos = res.data;
      });
    },
    submitForm() {
      this.errors.clear()
      this.loading = true;
      let submit;
      if (this.operacion == 'Crear') {
        submit = UsersResources.add(this.user);
      } else if (this.operacion == 'Editar') {
        submit = UsersResources.edit(this.user);
      }
      submit.then(this.submitSuccess).catch(this.submitError).finally(() => {
        this.loading = false;
      })
    },
    submitSuccess(response) {
      this.$notify.success({
        message: response.data.message,
      });
      this.$router.push({name: 'IndexUsuario'});
    },
    submitError(error) {
      this.$notify.error({
        message: error.response.data.message
      });
      this.errors.record(error.response.data.errors);
    }
  },
  created() {
    this.loadRoles();
    this.loadServicios();
  }
}
</script>
