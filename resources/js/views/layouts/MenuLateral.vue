<template>
  <el-menu
    :default-active="defaultActive"
    :router="true"
    :unique-opened="true"
    :collapse="collapsed"
    >
    <el-submenu index="admin">
      <template slot="title">
        <i class="fas fa-cogs"></i> <span class="menu-item-parent">Administración</span>
      </template>
      <el-menu-item index="Usuarios" :route="{name: 'AdminUsuarios'}"><i class="fas fa-users"></i> Usuarios</el-menu-item>
      <el-menu-item index="Roles" :route="{name: 'AdminRoles'}"><i class="fas fa-lock"></i> Roles</el-menu-item>
    </el-submenu>

    <el-submenu index="main">
      <template slot="title">
        <i class="fas fa-project-diagram"></i> <span class="menu-item-parent">Principal</span>
      </template>
      <el-menu-item index="public" :route="{name: 'Public'}"><i class="fas fa-briefcase"></i> Home</el-menu-item>
    </el-submenu>

  </el-menu>
</template>

<script>
import { EventBus } from "../../event-bus.js";
export default {
  data() {
    return {
      defaultActive: '',
      collapsed: true,
    }
  },
  methods: {
    setActive() {
      let menuElem = this.$el.getElementsByClassName('el-menu-item');
      for (let i = 0; i < menuElem.length; i++) {
        const route = menuElem[i].__vue__._props.route;
        if (_.find(this.$route.matched, {name: route.name})) {
          this.defaultActive = route.name;
          return;
        }
      }
    }
  },
  mounted() {
    this.setActive();
    EventBus.$on('toogle-menu-lateral', () => {
      this.collapsed = !this.collapsed;
    });
  }
}
</script>

<style scoped>
.el-menu {
  height: 100%;
}
</style>
