<template>
  <div>
    <el-row class="header-mantenedor">
      <slot name="header">
      </slot>
    </el-row>
    <el-row v-if="!ready" class="loading-modulos" v-loading="!ready"
      element-loading-text="Cargando Datos..."
      element-loading-spinner="el-icon-loading"
      element-loading-background="#ffffff"></el-row>
    <el-row v-else>
      <el-row class="body-mantenedor">
        <slot name="body"></slot>
      </el-row>

      <el-row class="pagination-mantenedor">
        <slot name="pagination"></slot>
      </el-row>
    </el-row>
  </div>
</template>

<script>
export default {
  props: ['ready']
}
</script>


<style>
.body-mantenedor {
  padding-bottom:30px;
}
.pagination-mantenedor {
  text-align: center;
}
.loading-modulos {
  min-height: 420px;
  width: 100%;
}
.el-table .cell {
  word-break: normal;
}
.button-wrapper {
  text-align: right;
}
</style>
