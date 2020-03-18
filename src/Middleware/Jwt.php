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
    private $user;

    public function __construct(App $app, User $user)
    {
        $this->app = $app;
        $this->user = $user;
    }

    public function handle($request, \Closure $next)
    {
        if (true === $this->app->jwt->verify()) {
            // 自动注入用户模型
            if ($this->user->hasInject()) {
                $user = $this->user->get();
                // 路由注入
                $request->user = $user;

                // 绑定当前用户模型
                $model = $this->user->getModel();
                $this->app->bind($model, $user);
            }

            return $next($request);
        }

        throw new JWTException('Token 验证不通过', 401);
    }
}
