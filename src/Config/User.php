<?php

declare (strict_types = 1);

namespace xiaodi\JWTAuth\Config;

class User
{
    protected $bind = false;

    protected $class = null;

    public function __construct(array $options)
    {
        if (!empty($options)) {
            foreach ($options as $key => $value) {
                $this->$key = $value;
            }
        }
    }

    public function getBind(): bool
    {
        return $this->bind;
    }

    public function getClass()
    {
        return $this->class;
    }
}
