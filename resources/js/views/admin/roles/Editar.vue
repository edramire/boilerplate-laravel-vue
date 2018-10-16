<template>
  <formulario-usuarios operacion="Editar" :role="role"></formulario-usuarios>
</template>

<script>
import Formulario from './Formulario.vue';
import RolesResources from '../../../endpoints/roles';
export default {
  data() {
    return {
      role: {}
    }
  },
  components: {
    formularioUsuarios: Formulario
  },
  created() {
    RolesResources.show({id: this.$route.params.id})
      .then((res) => this.role = res.data)
      .catch((error) => {
        console.error(error.response.data.message);
      })
  }
}
</script>
