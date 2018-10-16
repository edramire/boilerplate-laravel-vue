<template>
  <index-base :ready="ready">
    <template slot="header">
      <el-col :span="20">
        <h2>Listado de usuarios</h2>
      </el-col>
      <el-col :span="4" class="button-wrapper">
        <el-button type="success" @click="handleNew()">
          Agregar usuario
        </el-button>
      </el-col>
    </template>

    <template slot="body">
      <el-table :data="users" style="width: 100%">
        <el-table-column
          prop="name"
          label="Nombre"
          width="200">
        </el-table-column>
        <el-table-column
          prop="email"
          label="Email"
          width="200">
        </el-table-column>
        <el-table-column
          prop="roles"
          label="Roles"
          width="200">
            <template slot-scope="scope">
              <span v-for="role in scope.row.roles" :key="role.id">{{role.guard_name}}</span>
            </template>
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
  import UserResources from '../../../endpoints/users';

  export default {
    components: {
      IndexBase: IndexBase,
    },
    computed: {
      ready() {
        return (this.users)!==null;
      }
    },
    data() {
      return {
        users: null,
        pagination: {
          current_page: 0,
          from: 0,
          last_page: 0,
          per_page: 0,
          to: 0,
          total: 0,
        }
      }
    },
    methods: {
      handleEdit(index, row) {
        this.$router.push({
          name: 'EditarUsuario',
          params: {
            id: row.id
          }
        });
      },
      handleDelete(index, row) {
        console.log('Usuario eliminado');
      },
      handleNew() {
        this.$router.push({name: 'CrearUsuario'});
      },
      loadUsers() {
        UserResources.list().then((res) => {
          this.pagination = _.pick(res.data, [
            'current_page',
            'from',
            'last_page',
            'per_page',
            'to',
            'total',
          ]);
          this.users = res.data.data;
        });
      }
    },
    created() {
      this.loadUsers();
    }
  }
</script>

<style>

</style>
