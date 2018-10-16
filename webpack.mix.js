let mix = require('laravel-mix');

mix.sass('resources/sass/app.scss', 'public/css')
  .js('resources/js/app.js', 'public/js')
  .extract([
    'axios',
    'jquery',
    'element-ui',
    'lodash',
    'vue',
    'vue-axios',
    'vue-router'
  ])
  .autoload({
    jquery: ['jQuery', '$']
  })
  .options({
    imgLoaderOptions: {
      enabled: false
    },
  })
  .version();
