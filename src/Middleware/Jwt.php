<?php

namespace xiaodi\Middleware;

use think\App;
use think\Response;
use xiaodi\BearerToken;
use xiaodi\Exception\HasLoggedException;
use xiaodi\Exception\TokenAlreadyEexpired;
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
        } catch (HasLoggedException $e) {
            // 已在其它终端登录
            return Response::create(['message' => $e->getMessage(), 'code' => 50401], 'json', 401);
        } catch (TokenAlreadyEexpired $e) {
            // Token已过期
            return Response::create(['message' => $e->getMessage(), 'code' => 50402], 'json', 401);
        } catch (\Exception $e) {
            return Response::create(['message' => $e->getMessage(), 'code' => 50500], 'json', 500);
        }

        // 自动注入用户模型
        if ($this->jwt->injectUser()) {
            $user = $this->jwt->user();
            // 路由注入
            $request->user = $user;

            // 依赖注入
            $model = $this->jwt->userModel();
            $this->app->bind($model, $user);
        }

        $request->jwt = $this->jwt;

        return $next($request);
    }
}
