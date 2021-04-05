<?php

declare (strict_types = 1);

namespace xiaodi\JWTAuth\Config;

class SSO
{
    protected $enable = false;

    public function __construct(array $options)
    {
        if (!empty($options)) {
            foreach ($options as $key => $value) {
                $this->$key = $value;
            }
        }
    }

    public function getEnable(): bool
    {
        return $this->enable;
    }
}
