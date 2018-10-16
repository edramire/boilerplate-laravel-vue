<template>
    <div>
        <div class="gradient">
            <div class="estak-white-logo"/>
              <el-form label-position="left" label-width="0px" class="login-container">
                  <h3 class="title">Iniciar Sesión</h3>
                  <el-form-item prop="email" :error="errors.get('email')">
                      <el-input
                          type="text"
                          v-model="loginForm.email"
                          @change="errors.clear('email')"
                          @keyup.native.enter="submit"
                          auto-complete="off"
                          placeholder="Email"
                          suffix-icon="el-icon-message">
                      </el-input>
                  </el-form-item>
                  <el-form-item prop="password" :error="errors.get('password')">
                      <el-input
                          type="password"
                          v-model="loginForm.password"
                          @change="errors.clear('password')"
                          @keyup.native.enter="submit"
                          auto-complete="off"
                          placeholder="Contraseña"
                          suffix-icon="fa fa-key">
                      </el-input>
                  </el-form-item>
                  <el-checkbox v-model="checked" checked class="remember">Recordar password</el-checkbox>
                  <el-form-item style="width:100%;">
                      <el-button type="primary" style="width:100%;" @click.native.prevent="submit" :loading="loading" icon="fa fa-sign-in" @keyup.enter="submit">
                          Iniciar sesión
                      </el-button>
                  </el-form-item>
                  <el-form-item style=" width:100%;">
                      <el-button style="width:100%;" @click.native.prevent="register">Registrarse</el-button>
                  </el-form-item>
              </el-form>
            </div>
        </div>
    </div>
</template>

<script>
// import { requestLogin } from '../endpoints';
import Errors from '../common/Errors';

export default {
  data() {
    return {
      loading: false,
      loginForm: {
        email: '',
        password: ''
      },
      errors: new Errors(),
      checked: true
    };
  },
  methods: {
    submit() {
      this.loading = true;
      this.$auth.login({
        data: this.loginForm,
        rememberMe: this.checked,
        success() {
          this.$notify.success({
            message: 'Inicio de sesión satisfactorio'
          })
          this.$router.push({
            name: 'Home',
          });
        },
        error(error) {
          this.loading = false;
          if (error.response.data.error) {
            this.$notify.error({
              message: error.response.data.error
            });
          } else {
            this.errors.record(error.response.data);
          }
        },
        finally() {
          this.loading = false;
        }
      });
    },
    register() {
      this.$router.push({ name: 'Registro' });
    }
  }
};
</script>

<style lang="scss" scoped>

.gradient {
  width: 100%;
  box-sizing: border-box;
}

.login-container {
  top: -1%;
  position: relative;
  -webkit-border-radius: 5px;
  border-radius: 5px;
  -moz-border-radius: 5px;
  background-clip: padding-box;
  margin: 60px auto;
  width: 350px;
  padding: 35px 35px 15px 35px;
  background: #fff;
  border: 1px solid #eaeaea;

  .title {
    margin: 0px auto 40px auto;
    text-align: center;
    color: #505458;
  }
  .remember {
    margin: 0px 0px 35px 0px;
  }
  .is-error {
    margin-bottom: 35px;
  }
}
</style>
