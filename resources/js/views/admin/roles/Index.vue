<template>
  <index-base :ready="ready">
    <template slot="header">
      <el-col :span="20">
        <h2>Listado de Roles</h2>
      </el-col>
      <el-col :span="4" class="button-wrapper">
        <el-button type="success" @click="handleNew()">
          Agregar rol
        </el-button>
      </el-col>
    </template>

    <template slot="body">
      <el-table :data="roles" style="width: 100%">
        <el-table-column
          prop="guard_name"
          label="Nombre"
          width="200">
        </el-table-column>
        <el-table-column
          prop="name"
          label="Nombre interno"
          width="200">
        </el-table-column>
        <el-table-column
          label="Acciones">
          <template slot-scope="scope">
            <el-button-group>
              <el-button type="warning" size="mini"
              @click="handleEdit(scope.$index, scope.row)">
                <i class="fas fa-pencil-alt"></i>
              </el-button>
              <el-button type="danger" size="mini"
              @click="handleDelete(scope.$index, scope.row)">
                <i class="fas fa-trash"></i>
              </el-button>
            </el-button-group>
          </template>
        </el-table-column>
      </el-table>
    </template>

    <template slot="pagination">
      <el-pagination
        :page-size="pagination.per_page"
        :pager-count="7"
        :current-page.sync="pagination.current_page"
        :total="pagination.total"
        layout="prev, pager, next"
        >
      </el-pagination>
    </template>
  </index-base>
</template>

<script>
  import IndexBase from '../AdminIndexBase.vue';
  import RolesResources from '../../../endpoints/roles';

  export default {
    components: {
      IndexBase: IndexBase,
    },
    computed: {
      ready() {
        return (this.roles)!== null;
      }
    },
    data() {
      return {
        roles: null,
        pagination: {
          current_page: 0,
          from: 0,
          last_page: 0,
          per_page: 0,
          to: 0,
          total: 0,
        },
      }
    },
    methods: {
      handleEdit(index, row) {
        this.$router.push({
          name: 'EditarRoles',
          params: {
            id: row.id
          }
        });
      },
      handleDelete(index, row) {
        console.log('Rol eliminado');
      },
      handleNew() {
        this.$router.push({name: 'CrearRoles'});
      },
      loadRoles() {
        RolesResources.list().then((res) => {
          this.pagination = _.pick(res.data, [
            'current_page',
            'from',
            'last_page',
            'per_page',
            'to',
            'total',
          ]);
          this.roles = res.data.data;
        });
      },
    },
    created() {
      this.loadRoles();
    }
  }
</script>

<style>

</style>
