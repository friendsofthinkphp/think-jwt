<?php

declare (strict_types = 1);

namespace xiaodi\JWTAuth\Config;

class Manager
{
    protected $prefix = 'jwt';
    protected $blacklist = 'blacklist';
    protected $whitelist = 'whitelist';

    public function __construct(array $options = [])
    {
        if (!empty($options)) {
            foreach ($options as $key => $value) {
                $this->$key = $value;
            }
        }
    }

    public function getPrefix(): string
    {
        return $this->prefix;
    }

    public function getBlacklist(): string
    {
        return $this->blacklist;
    }

    public function getWhitelist(): string
    {
        return $this->whitelist;
    }
}
