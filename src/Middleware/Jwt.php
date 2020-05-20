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

    public function handle($request, \Closure $next, $type = 'admin')
    {
        if (true === $this->app->jwt->config($type)->verify()) {

            $user = $this->app['jwt.user'];
            // 自动注入用户模型
            if ($user->hasInject()) {
                $userModel = $user->get();
                // 路由注入
                $request->user = $userModel;

                // 绑定当前用户模型
                $model = $user->getModel();
                $this->app->bind($model, $userModel);
            }

            return $next($request);
        }

        throw new JWTException('Token 验证不通过', 401);
    }
}
