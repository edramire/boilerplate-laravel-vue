<template>
<div>

  <div v-if="$auth.ready()">
    <el-container style="height: 100%;">
      <el-header>
        <header-vue/>
      </el-header>
      <el-container >
        <el-main>
          <main-content style="margin-bottom:70px"/>
        </el-main>
      </el-container>
      <el-footer>
        <el-row>
          <el-col :span="1">
            <!-- <img src="https://vignette.wikia.nocookie.net/althistory/images/1/1e/Logo_del_Ministerio_de_Salud_%28Chile%29.png/revision/latest?cb=20131130054249&path-prefix=es"
            width="50px"
            height="50px"
            style="margin-top:-4px; margin-right: -60px;"/> -->
          </el-col>
          <el-col :span="6">
            <div style="margin-top: 10px;">
              <b>Aphix</b>
            </div>
          </el-col>
          <el-col :span="1" :offset="13">
            <div style="margin-top: 10px;"><b>Contacto:</b></div>
          </el-col>
          <el-col :span="3" >
              <div><b>+56 9 00000000</b></div>
              <div><b>info@aphix.cl</b></div>
          </el-col>
        </el-row>
      </el-footer>
    </el-container>
  </div>
  <div v-if="!$auth.ready()">
    <div class="loading-modulos" v-loading="true"
      element-loading-text="Cargando Datos..."
      element-loading-spinner="el-icon-loading"
      element-loading-background="#ffffff">
    </div>
  </div>
</div>
</template>

<script>
  import HeaderVue from './Header.vue';
  import MainContent from './content.vue';
  import { EventBus } from "../../event-bus.js";

  export default {
    components: {
      HeaderVue,
      MainContent,
    },
    beforeCreate() {
      if (!this.$auth.watch.authenticated) {
        this.$router.push({name: 'Login'});
      }
    },
  }
</script>

<style scoped>
  .el-header, .el-footer {
    background-color: #016cbc;
    color: #fff;
    text-align: center;
    padding-top: 10px;
  }

  .el-footer {
    position: fixed;
    left: 0;
    bottom: 0;
    width: 100%;
  }

  body > .el-container {
    margin-bottom: 40px;
  }

</style>
