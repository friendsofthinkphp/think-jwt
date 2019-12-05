<?php

namespace xiaodi\Middleware;

use think\App;
use think\Response;
use xiaodi\BearerToken;
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
        try {
            $token = $this->bearerToken->getToken();
            $this->jwt->verify($token);
        } catch (\Exception $e) {
            return Response::create(['message' => $e->getMessage()], 'json');
        }

        // 自动注入用户模型
        if ($this->jwt->injectUser()) {
            $user = $this->jwt->user();
            // 路由注入
            $request->user = $user;

            // 依赖注入
            $model = $this->jwt->getUserModel();
            $this->app->bind($model, $user);
        }

        $request->jwt = $this->jwt;

        return $next($request);
    }
}
