<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Middleware;

use think\App;
use think\Response;
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
        if ($request->method(true) == 'OPTIONS') {
            return Response::create()->code(204);
        }

        if (true === $this->app->get('jwt')->store($store)->verify()) {

            if ($this->app->get('jwt.user')->getBind()) {
                if ($user = $this->app->get('jwt.user')->find()) {
                    // 路由注入
                    $request->user = $user;

                    // 绑定当前用户模型
                    $class = $this->app->get('jwt.user')->getClass();
                    $this->app->bind($class, $user);

                    // 绑定用户后一些业务处理
                    $this->bindUserAfter($request);
                } else {
                    throw new JWTException('登录校验已失效, 请重新登录', 401);
                }
            }

            return $next($request);
        }

        throw new JWTException('Token 验证不通过', 401);
    }

    protected function bindUserAfter($request)
    {
        // 当前用户
        // $request->user
    }
}
