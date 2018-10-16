<?php

use Illuminate\Database\Seeder;
use App\Models\User;
use App\Models\Role;
use Illuminate\Support\Facades\Artisan;

class AdminSeeder extends Seeder
{
    /**
     * Run the database seeds.
     *
     * @return void
     */
    public function run()
    {
        $user = User::where(['name' => 'admin'])->first();
        if (!$user) {
            $user = User::create([
                'email' => 'admin@admin.cl',
                'name' => 'admin',
                'password' => '123'
            ]);
        }
        $adminRole = Role::where(['name' => 'admin'])->first();

        if (! $user->hasRole($adminRole->name)) {
            $user->roles()->sync([$adminRole->id]);
        }
    }
}
