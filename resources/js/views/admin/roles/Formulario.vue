<template>
  <formulario-base>
    <template slot="header">
      <el-col :span="20">
        <h2>{{operacion}} roles</h2>
      </el-col>
      <el-col :span="4">
        <router-link :to="{name: 'IndexRoles'}">
          <el-button type="primary">Atrás</el-button>
        </router-link>
      </el-col>
    </template>

    <template slot="body">
      <el-form ref="form" :model="role" :rules="validation" label-width="200px">
        <el-form-item label="Nombre" prop="guard_name">
          <el-input v-model="role.guard_name" :error="errors.get('guard_name')"></el-input>
        </el-form-item>
        <el-form-item label="Nombre Interno" prop="name">
          <el-input v-model="role.name" :error="errors.get('name')"></el-input>
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
import RolesResources from '../../../endpoints/roles';
import Errors from '../../../common/Errors';

export default {
  components: {
    formularioBase: FormularioBase
  },
  props: ['operacion', 'role'],
  data() {
    return {
      loading: false,
      errors: new Errors(),
      validation: {}
    }
  },
  methods: {
    submitForm() {
      this.errors.clear()
      this.loading = true;
      let submit;
      if (this.operacion == 'Crear') {
        submit = RolesResources.add(this.role);
      } else if (this.operacion == 'Editar') {
        submit = RolesResources.edit(this.role);
      }
      submit.then(this.submitSuccess).catch(this.submitError).finally(() => {
        this.loading = false;
      })
    },
    submitSuccess(response) {
      this.$notify.success({
        message: response.data.message,
      });
      this.$router.push({name: 'IndexRoles'});
    },
    submitError(error) {
      this.$notify.error({
        message: error.response.data.message
      });
      this.errors.record(error.response.data.errors);
    }
  },
}
</script>
