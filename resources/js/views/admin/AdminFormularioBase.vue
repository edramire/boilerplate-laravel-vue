<template>
  <el-container>
    <el-header>
      <slot name="header">
      </slot>
    </el-header>

    <el-main>
      <slot name="body">
      </slot>
    </el-main>

    <el-footer>
      <slot name="footer">
      </slot>
    </el-footer>
  </el-container>
</template>

<style lang="scss">
.el-form-item {
  width: 70%;
}
.el-select {
  width: 100%;
}
</style>
