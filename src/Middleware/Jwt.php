<?php

namespace xiaodi\Middleware;

use think\App;
use xiaodi\BearerToken;
use xiaodi\Exception\JWTException;
use xiaodi\Jwt as Ac;

/**
 * 中间件.
 */
class Jwt
{
    private $jwt;
    private $app;
    private $bearerToken;

    public function __construct(App $app, BearerToken $bearerToken, Ac $jwt)
    {
        $this->jwt = $jwt;
        $this->app = $app;
        $this->bearerToken = $bearerToken;
    }

    public function handle($request, \Closure $next)
    {
        $token = $this->bearerToken->getToken();
        if (true === $this->jwt->verify($token)) {
            // 自动注入用户模型
            if ($this->jwt->injectUser()) {
                $user = $this->jwt->user();
                // 路由注入
                $request->user = $user;

                // 依赖注入
                $model = $this->jwt->userModel();
                $this->app->bind($model, $user);
            }

            $request->jwt = $this->jwt;

            return $next($request);
        }

        throw new JWTException('Token 验证不通过', 401);
    }
}
