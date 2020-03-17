<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Handle;

class Header extends RequestToken
{
    public function handle()
    {
        $authorization = $this->app->request->header('authorization');

        if (!$authorization || strpos($authorization, 'Bearer ') !== 0) {
            return;
        }

        return substr($authorization, 7);
    }
}
