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

            $user = $this->app['jwt.user'];

            if ($user->bind()) {
                $info = $user->get();
                if (!$info){
                    throw new JWTException('没有此用户', 401);
                } 
                
                // 路由注入
                $request->user = $info;
                
                // 绑定当前用户模型
                $model = $info->getClass();
                $this->app->bind($model, $info);
            }

            return $next($request);
        }

        throw new JWTException('Token 验证不通过', 401);
    }
}
