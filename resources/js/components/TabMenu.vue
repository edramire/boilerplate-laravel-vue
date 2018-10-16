<template>
  <el-tabs
    type="border-card"
    @tab-click="handleSelectedTab"
    v-model="selected"
    :tab-position="tabPosition"
    stretch
    class="tab-menu">
    <el-tab-pane v-for="op in options" :key="op.name" :name="op.name" :disabled="op.disabled">
      <span slot="label">
        <i v-if="op.ico" :class="'fas ' + op.ico"></i>
        {{op.label}}
      </span>
      <router-view v-if="selected==op.name"></router-view>
    </el-tab-pane>
  </el-tabs>
</template>

<script>
export default {
  props: [
    'default',
    'options',
    'tabPosition',
  ],
  data() {
    return {
      selected: '',
    }
  },
  methods: {
    handleSelectedTab(op) {
      this.$router.push({name: op._props.name});
    },
    setActive() {
      let tabActual = _.find(this.options, (op) => _.find(this.$route.matched, {name: op.name}));
      if (!tabActual) {
        this.selected = this.default;
      } else {
        this.selected = tabActual.name;
      }
    },
    setDefaultOptions() {
      this.default = this.default || this.options[0].name;
      this.tabPosition = this.tabPosition || 'left';
    },
  },
  created() {
    this.setDefaultOptions();
    this.setActive();
  }
}
</script>


<style lang="sass" scoped>

</style>
