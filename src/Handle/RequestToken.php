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
     * 获取请求Token.
     *
     * @param string|array $handle
     *
     * @return string
     */
    public function get($handle): string
    {
        if (is_string($handle)) {
            $handles = explode('|', $handle);
        }

        foreach ($handles as $handle) {
            if (in_array($handle, $this->handles)) {
                $namespace = '\\xiaodi\\JWTAuth\Handle\\' . $handle;
                $token = (new $namespace($this->app))->handle();
                if ($token) {
                    $this->token = $token;
                    break;
                }
                continue;
            } else {
                throw new JwtException('不支持此方式获取.', 500);
            }
        }

        if (!$this->token) {
            throw new JwtException('获取Token失败.', 500);
        }

        return $this->token;
    }
}
