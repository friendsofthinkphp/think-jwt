<?php

namespace think\JwtAuth\Middleware;

use think\JwtAuth\JwtAuth as Jwt;
use think\Response;
use think\JwtAuth\Exception\TokenNotAvailableException;
/**
 * 中间件
 * 
 */
class JwtAuth
{
    public function handle($request, \Closure $next)
    {
        $token = $request->header(config('jwt-auth.header'));

        if (empty($token)) {
            throw new \Exception('miss token.');
        }
        
        $jwt = new Jwt();

        try {
            $jwt->verify($token);
        } catch(\think\JwtAuth\Exception\HasLoggedException $e) {
            // 账号已在其它地方登录
        } catch(\think\JwtAuth\Exception\TokenExpiredException $e) {
            // Token 已过期
        }

        // 自动注入用户模型
        if (config('jwt-auth.user.allow')) {
            $request->user = $jwt->user();
        }

        return $next($request);
    }
}
