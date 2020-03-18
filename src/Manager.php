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

    /**
     * 处理登录时
     *
     * @param Token $token
     * @return void
     */
    public function login(Token $token)
    {
        // TODO 但凡获取新token后 都把以前的注销(黑名单)
        // $jti = $token->getClaim('jti');
    }

    /**
     * 处理登出时
     *
     * @param Token $token
     * @return void
     */
    public function logout(Token $token)
    {
        $this->blacklist->add($token);
    }

    /**
     * 处理刷新时
     *
     * @param Token $token
     * @return void
     */
    public function refresh(Token $token)
    {
        // 注销此Token
        $this->logout($token);
    }

    /**
     * 是否存在黑名单.
     *
     * @param Token $token
     *
     * @return bool
     */
    public function hasBlacklist(Token $token)
    {
        return $this->blacklist->has($token);
    }
}
