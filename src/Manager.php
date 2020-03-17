<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth;

use Lcobucci\JWT\Token;

class Manager
{
    private $blacklist;

    public function __construct(Blacklist $blacklist)
    {
        $this->blacklist = $blacklist;
    }

    public function login(Token $token)
    {
    }

    public function logout(Token $token)
    {
        $this->blacklist->add($token);
    }

    public function refresh(Token $token)
    {
    }

    /**
     * Undocumented function.
     *
     * @param Token $token
     *
     * @return bool
     */
    public function hasBlacklist(Token $token)
    {
        return $this->blacklist->add($token);
    }
}
