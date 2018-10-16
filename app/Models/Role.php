<?php

namespace App\Models;

use App\Filters\Filterable;

class Role extends \Spatie\Permission\Models\Role
{
    use Filterable;
}
