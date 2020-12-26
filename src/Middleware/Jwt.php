<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Middleware;

use think\App;
use xiaodi\JWTAuth\Exception\JWTException;

/**
 * 中间件.
 */
class Jwt
{
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    public function handle($request, \Closure $next, $store = null)
    {
        // 暂时修复 6.0.3 options 问题
        if ($request->isOptions()) {
            return $next($request);
        }

        if (true === $this->app->get('jwt')->store($store)->verify()) {

            $user = $this->app->get('jwt.user');

            if ($user->getBind()) {
                if ($info = $user->get()) {
                    // 路由注入
                    $request->user = $info;

                    // 绑定当前用户模型
                    $model = $user->getClass();
                    $this->app->bind($model, $info);
                }
            } else {
                throw new JWTException('登录校验已失效, 请重新登录', 401);
            }

            return $next($request);
        }

        throw new JWTException('Token 验证不通过', 401);
    }
}
