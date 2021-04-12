<?php

declare(strict_types=1);

namespace xiaodi\JWTAuth\Handle;

class Header extends RequestToken
{
    public function handle()
    {
        $authorization = $this->app->request->header('authorization');

        if (!$authorization) {
            return;
        }

        if (strpos($authorization, 'Bearer ') === 0) {
            return substr($authorization, 7);
        } else {
            return $authorization;
        }
    }
}
