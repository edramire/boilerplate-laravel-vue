<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class LoginController extends Controller
{
    use AuthenticatesUsers;

    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function login(Request $request)
    {
        $this->validate($request, [
            'email' => 'required',
            'password' => 'required'
        ]);

        if (!Auth::once($request->except('_token'))) {
            return response()->json(['email' => ['Credenciales no validas']], 422);
        }

        Auth::user()->updateToken()->save();
        $token = Auth::user()->api_token;
        return response()
            ->json(compact('token'))
            ->header('Authorization', $token);
    }

    public function logout(Request $request)
    {
        Auth::logout();
    }
}
