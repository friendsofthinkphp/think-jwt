<?php

namespace xiaodi\Contracts;

interface JwtMiddlewareHandleInterface
{
    /**
     * 已在其它终端登录，请重新登录.
     */
    public function hasLogged();

    /**
     * Token 已过期
     */
    public function tokenExpired();

    /**
     * 数据验证失败.
     */
    public function verifyData();

    /**
     * Token 暂未可用.
     */
    public function tokenNotAvailable();
}
