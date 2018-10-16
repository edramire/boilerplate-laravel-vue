<template>
  <formulario-usuarios operacion="Crear" :user="user"></formulario-usuarios>
</template>

<script>
import Formulario from './Formulario.vue';
import UsersResources from '../../../endpoints/users';
export default {
  data() {
    return {
      user: {
        establecimientos: [],
        servicios: '',
        role: null,
      }
    }
  },
  components: {
    formularioUsuarios: Formulario
  }
}
</script>
