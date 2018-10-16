window._ = require('lodash');
window.Popper = require('popper.js').default;
try {
  window.$ = window.jQuery = require('jquery');
  require('bootstrap');
} catch (e) {}

window.axios = require('axios');
window.axios.defaults.headers.common['X-Requested-With'] = 'XMLHttpRequest';

let token = window.Laravel.csrfToken;

if (token) {
  window.axios.defaults.headers.common['X-CSRF-TOKEN'] = token;
} else {
  console.error('CSRF token not found: https://laravel.com/docs/csrf#csrf-x-csrf-token');
}

// window.axios.defaults.headers['Content-Type'] = 'application/json';
