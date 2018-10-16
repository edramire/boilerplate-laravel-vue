<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;

use App\Models\User;
use App\Models\Role;
use App\Notifications\WelcomeNotification;
use App\Filters\UserFilter;
use App\Http\Requests;
use App\Http\Controllers\ApiController;

class UsersController extends ApiController
{
    public function index(UserFilter $filter)
    {
        return User::with('roles')->filter($filter)->paginate();
    }

    public function me(Request $request)
    {
        if (!$request->user()) {
            return;
        }
        $user = $request->user()->load(['roles']);
        $user->role = $user->roles[0]->name;
        return [
            'data' => $user,
        ];
    }

    public function show(User $user)
    {
        $user->load(['establecimientos', 'servicios', 'roles']);
        $user->role_id = $user->roles[0]->id;
        return $user;
    }

    public function store(Request $request)
    {
        $this->validate($request, [
            'name'     => 'required|max:255',
            'email'    => 'required|email|max:255|unique:users',
            'password' => 'required|confirmed|min:6',
            'role_id'    => 'exists:roles,id',
        ]);

        $user = User::create($request->all());
        $user->roles()->sync([$request->role_id]);

        return $this->respondStore();
    }

    public function update(Request $request, $id)
    {
        $this->validate($request, [
            'name'     => 'sometimes|required|max:255',
            'email'    => 'sometimes|required|email|max:255|unique:users,email,' . $id,
            'password' => 'sometimes|required|confirmed|min:6',
            'role_id'    => 'exists:roles,id',
        ]);
        $user = User::find($id)->fill($request->all());
        $user->save();
        $user->roles()->sync([$request->role_id]);
        return $this->respondUpdate();
    }

    public function destroy(User $user)
    {
        $user->delete();

        return $this->respondDestroy();
    }
}
