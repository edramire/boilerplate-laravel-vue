<template>
  <formulario-usuarios operacion="Editar" :user="user"></formulario-usuarios>
</template>

<script>
import Formulario from './Formulario.vue';
import UsersResources from '../../../endpoints/users';
export default {
  data() {
    return {
      user: {}
    }
  },
  components: {
    formularioUsuarios: Formulario
  },
  created() {
    UsersResources.show({id: this.$route.params.id})
      .then((res) => {
        this.user = res.data;
        this.user.servicios = this.user.servicios[0];
      })
      .catch((error) => {
        console.error(error.response.data.message);
      })
  }
}
</script>
