<?php

namespace xiaodi\think\jwt;

use think\App;
use think\Request;
use think\Response;
use think\Middleware;
use xiaodi\think\jwt\Handle\RequestToken;

class JwtAuthMiddware extends Middleware
{
    /**
     * @param App
     */
    protected $app;

    public function __construct(App $app)
    {
        $this->app = $app;
    }

    public function handle(Request $request, \Closure $next, $source = 'Header|Url')
    {
        if ($request->method(true) == 'OPTIONS') {
            return Response::create()->code(204);
        }

        try {
            $requestToken = new RequestToken($this->app);
            $token = $requestToken->get($source);

            if (true === $this->app->get('jwt')->verify($token)) {
                $this->app->bind($this->app->jwt->getConfig()->getUserModel(), $this->app->jwt->getUser());
                return $next($request);
            }

            return Response::create()->code(401);
        } catch (\Exception $e) {
            return Response::create($e->getMessage())->code(500);
        }
    }
}
