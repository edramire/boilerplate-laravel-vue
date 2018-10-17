<template>
<div>
  <el-row>
    <el-col :span="14"><h2>Panel de administración</h2></el-col>
  </el-row>
  <tab-menu :options="opciones" default="Usuarios" tab-position="top"></tab-menu>
</div>
</template>

<script>
import TabMenu from "../../components/TabMenu.vue";

export default {
  components: {
    TabMenu,
  },
  data() {
    return {
      opciones: [
        {label:'Usuarios', name:'AdminUsuarios', ico:'fa-users'},
        {label:'Roles', name:'AdminRoles', ico:'fa-globe'},
      ],
    }
  },
}
</script>
