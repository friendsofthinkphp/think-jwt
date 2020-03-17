<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Handle;

use think\App;
use xiaodi\JWTAuth\Exception\JWTException;

class RequestToken
{
    protected $handles = ['Header', 'Url', 'Cookie'];

    protected $token;

    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    /**
     * 获取请求Token
     *
     * @param string $handle
     * @return String
     */
    public function getToken(string $handle): String
    {
        if (!in_array($handle, $this->handles)) {
            throw new JwtException('不支持只方式获取.', 500);
        }

        $this->token = (new Header($this->app))->handle();

        if (!$this->token) {
            throw new JwtException('获取Token失败.', 500);
        }

        return $this->token;
    }
}
