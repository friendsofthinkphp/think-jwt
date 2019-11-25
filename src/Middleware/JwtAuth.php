<?php

namespace xiaodi\Middleware;

use think\App;
use think\facade\Route;
use xiaodi\BearerToken;
use xiaodi\Exception\HasLoggedException;
use xiaodi\Exception\TokenExpiredException;

/**
 * 中间件.
 */
class JwtAuth
{
    private $auth;

    public function __construct(App $app, BearerToken $bearerToken)
    {
        Route::allowCrossDomain();

        $this->auth = $app->auth;
        $this->bearerToken = $bearerToken;
    }

    public function handle($request, \Closure $next)
    {
        $token = $this->bearerToken->getToken();

        try {
            $this->auth->verify($token);
        } catch (HasLoggedException $e) {
            // 账号已在其它地方登录
        } catch (TokenExpiredException $e) {
            // Token 已过期
        }

        // 自动注入用户模型
        if ($this->auth->injectUser()) {
            $request->user = $this->auth->user();
        }

        return $next($request);
    }
}
