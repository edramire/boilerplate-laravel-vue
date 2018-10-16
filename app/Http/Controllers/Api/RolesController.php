<?php

namespace App\Http\Controllers\Api;

use Illuminate\Http\Request;

use App\Models\Role;
use App\Filters\RoleFilter;
use App\Http\Requests;
use App\Http\Controllers\ApiController;
use Spatie\Permission\Models\Permission;

class RolesController extends ApiController
{
    public function index(RoleFilter $filter)
    {
        return Role::with('permissions')->filter($filter)->oldest()->paginate();
    }

    public function show(Role $role)
    {
        $role->permissions = $role->permissions()->pluck('id');

        return $role;
    }

    public function store(Request $request)
    {
        $this->validate($request, [
            'name' => 'required|max:255|unique:roles',
            'guard_name' => 'required|max:255',
        ]);
        $role = Role::create($request->only(['name', 'guard_name']));
        // request()->user()->roles()->sync([$request->role_id]);
        return $this->respondStore();
    }

    public function update(Request $request, Role $role)
    {
        $this->validate($request, [
            'name' => 'sometimes|required|max:255|unique:roles,name,' . $role->id,
            'guard_name' => 'sometimes|required|max:255',
        ]);

        $role->fill($request->only(['name', 'guard_name']))->save();

        // Permission::whereIn('id', $request->permissions)->pluck('name');
        return $this->respondUpdate();
    }

    public function destroy(Role $role)
    {
        $role->delete();

        return $this->respondDestroy();
    }
}
