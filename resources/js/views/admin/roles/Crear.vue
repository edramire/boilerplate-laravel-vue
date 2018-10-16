<template>
  <formulario-usuarios operacion="Crear" :role="role"></formulario-usuarios>
</template>

<script>
import Formulario from './Formulario.vue';

export default {
  data() {
    return {
      role: {}
    }
  },
  components: {
    formularioUsuarios: Formulario
  }
}
</script>
