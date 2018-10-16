<template>
  <el-row>
    <el-col :span="10" class="titulo-pagina">
      <span>APHIX</span>
    </el-col>
    <el-col :span="14" class="pull-right">
      <el-button class="transparent-button header-button-menu">
        <router-link class="home-link" :to="{name: 'Proyectos'}">
          <i class="fa fa-home"></i>
        </router-link>
      </el-button>
      <el-dropdown class="perfil transparent-button header-button-menu" trigger="click">
        <span class="el-dropdown-link">
          <el-row>
            <el-col :span="22">
              <i class="fa fa-user"></i> {{user.name}}
              <br>
              <small>({{user.roles[0].guard_name}})</small>
            </el-col>
            <el-col :span="2">
              <i class="el-icon-arrow-down el-icon--right"></i>
            </el-col>
          </el-row>
        </span>
        <el-dropdown-menu slot="dropdown">
          <el-dropdown-item v-if="$auth.check('admin')" @click.native="config"><i class="fas fa-cogs"></i> Configuración</el-dropdown-item>
          <el-dropdown-item @click.native="logout" :divided="$auth.check('admin')">Cerrar Sesión</el-dropdown-item>
        </el-dropdown-menu>
      </el-dropdown>
    </el-col>
  </el-row>
</template>

<script>
import { EventBus } from "../../event-bus.js";

export default {
  data() {
    return {
      user: {},
    };
  },
  methods: {
    logout() {
      this.$confirm('¿Estas seguro que quieres salir?', 'Confirmar')
        .then(() => {
          this.$auth.logout({
            makeRequest: true,
            success: () => {},
            redirect: { name: 'Login' }
          });
        }).catch(() => {
          this.$router.push({name: 'Login'});
        });
    },
    config() {
      this.$router.push({name: 'Administracion'});
    },
    loadData() {
      this.user = this.$auth.user();
    },
  },
  created() {
    this.loadData();
  },
}
</script>

<style scoped>
  .titulo-pagina{
    font-weight: bold;
    text-align: left;
  }
  .perfil {
    background-color: #016cbc;
    color: #fff;
    text-align: center;
    padding-top: 0px;
    cursor: pointer;
    font-weight: bold;
  }
  .home-link {
    margin-right: 25px;
    margin-left: 25px;
    font-size:17px;
    color: white;
  }
  .transparent-button {
    background-color: #016cbc;
    border: none;
  }
  .pull-right {
    text-align: right;
  }
  .header-button-menu {
    display: inline-block;
    vertical-align: middle;
    line-height: normal;
  }
</style>
