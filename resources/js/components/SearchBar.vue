<template>
  <el-row>
    <el-form :inline="true">
      <el-form-item>
        <el-input v-model="query" @keyup.enter.native="loadQuery" placeholder="Consulta por campo"></el-input>
      </el-form-item>
      <el-form-item>
        <el-button type="primary" @click="loadQuery">Consulta</el-button>
      </el-form-item>
    </el-form>
  </el-row>
</template>

<script>
import {EventBus} from '../event-bus.js';
export default {
  data() {
    return {
      query: null,
    };
  },
  methods: {
    loadQuery() {
      EventBus.$emit('send-query', this.query);
    }
  },
}
</script>
