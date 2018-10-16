<?php

namespace App\Filters;

class RoleFilter extends QueryFilter
{
    public function name($value = null)
    {
        return $this->builder->where('name', 'ilike', "%$value%");
    }

    public function guard_name($value = null)
    {
        return $this->builder->where('guard_name', 'ilike', "%$value%");
    }

    public function permissions($value = null)
    {
        return $this->builder->whereHas('permissions', function ($q) use ($value) {
            $q->where('guard_name', 'ilike', "%$value%");
        });
    }
}
