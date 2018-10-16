<template>
  <el-radio-group v-model="selected" @change="changeSelected">
    <el-radio-button
      v-for="op in options"
      :key="op.route"
      :label="op.route"
      >
      {{op.label}}
      <el-badge v-if="op.valor" class="mark" :value="op.valor"/>
    </el-radio-button>
  </el-radio-group>
</template>

<script>
export default {
  props: ['options', 'handleSelected'],
  data() {
    return {
      selected: '',
    }
  },
  methods: {
    activo() {
      let actual = _.find(this.options, (op) => _.find(this.$route.matched, {name: op.route}));
      if (!actual) {
        this.selected = this.options[0].route;
      } else {
        this.selected = actual.route;
      }
    },
    changeSelected(route) {
      let opSelected = _.find(this.options, {route: route})
      if (opSelected.handleClick) {
        opSelected.handleClick();
        this.activo()
        return
      }
      this.goToRoute()
    },
    goToRoute() {
      this.$router.push({name: this.selected});
      this.activo()
    }
  },
  mounted() {
    this.activo();
    this.$watch('$route.path', val => {
      this.activo();
    });
  },
}
</script>
