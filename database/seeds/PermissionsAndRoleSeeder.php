<?php

use Illuminate\Database\Seeder;
use App\Models\Role;
use Spatie\Permission\Models\Permission;

class PermissionsAndRoleSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        app()['cache']->forget('spatie.permission.cache');
        // permissions
        $permissions = [
            [
                'name' => 'admin',
                'guard_name' => 'Administrador del sistema'
            ],
        ];
        foreach ($permissions as $i => $permission) {
            $permissions[$i] = Permission::firstOrCreate($permission);
        }

        // create all permission
        $permissions = $permissions + [
        ];

        $admin;
        foreach ($permissions as $i => $data) {
            $role = Role::firstOrNew(['name' => $data['name']]);
            $role->guard_name = $data['guard_name'];
            $role->save();
            if ($i == 0) {
                $admin = $role;
            }
        }

        // add roles to admin
        foreach ($permissions as $permission) {
            if (! $admin->hasPermissionTo($permission)) {
                $admin->givePermissionTo($permission->name);
            }
        }
        app()['cache']->forget('spatie.permission.cache');
    }
}
