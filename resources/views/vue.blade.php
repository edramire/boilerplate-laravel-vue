@extends('layout')

@section('styles')
    <link rel="stylesheet" href="{{ mix('css/app.css') }}">
@endsection

@section('body')
    <body>
        <div id="app">
        </div>
        <script src="{{ mix('js/manifest.js') }}"></script>
        <script src="{{ mix('js/vendor.js') }}"></script>
        <script src="{{ mix('js/app.js') }}"></script>
    </body>
@endsection
