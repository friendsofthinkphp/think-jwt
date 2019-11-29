<?php

namespace xiaodi\Middleware;

use think\App;
use think\Response;
use think\facade\Route;
use xiaodi\BearerToken;
use xiaodi\Exception\HasLoggedException;
use xiaodi\Exception\TokenExpiredException;

/**
 * 中间件.
 */
class Jwt
{
    private $jwt;
    private $app;

    public function __construct(App $app, BearerToken $bearerToken)
    {
        Route::allowCrossDomain();

        $this->jwt = $app->jwt;
        $this->app = $app;
        $this->bearerToken = $bearerToken;
    }

    public function handle($request, \Closure $next)
    {
        $token = $this->bearerToken->getToken();

        try {
            $this->jwt->verify($token);
        } catch(\Exception $e) {
            return Response::create(['message' => $e->getMessage()], 'json');
        }

        // 自动注入用户模型
        if ($this->jwt->injectUser()) {
            $request->user = $this->jwt->user();
        }

        $request->jwt = $this->jwt;
        return $next($request);
    }
}
