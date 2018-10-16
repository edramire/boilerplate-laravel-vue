<?php

use Illuminate\Http\Request;

/*
|--------------------------------------------------------------------------
| API Routes
|--------------------------------------------------------------------------
|
| Here is where you can register API routes for your application. These
| routes are loaded by the RouteServiceProvider within a group which
| is assigned the "api" middleware group. Enjoy building your API!
|
*/

Route::middleware('auth:api')->namespace('Api')->group(function () {
    Route::middleware('admin')->group(function () {
        Route::resources(['users' => 'UsersController']);
        Route::resources(['roles' => 'RolesController']);
    });
    Route::get('user', 'UsersController@me');
});
