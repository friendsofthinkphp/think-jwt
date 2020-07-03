<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Middleware;

use think\App;
use xiaodi\JWTAuth\Exception\JWTException;
use xiaodi\JWTAuth\User;

/**
 * 中间件.
 */
class Jwt
{
    private $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    public function handle($request, \Closure $next, $store = 'admin')
    {
        // 暂时修复 6.0.3 options 问题
        if ($request->isOptions()) {
            return $next($request);
        }
        
        if (true === $this->app->jwt->store($store)->verify()) {

            $jwt_user = $this->app['jwt.user'];

            if ($jwt_user->bind()) {
                $user = $jwt_user->get();
                // 路由注入
                $request->user = $user;

                // 绑定当前用户模型
                $model = $jwt_user->getClass();
                $this->app->bind($model, $user);
            }

            return $next($request);
        }

        throw new JWTException('Token 验证不通过', 401);
    }
}
