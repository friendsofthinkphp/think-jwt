<?php

declare(strict_types=1);

namespace xiaodi\think\jwt\Handle;

class Cookie extends RequestToken
{
    public function handle()
    {
        return $this->app->cookie->get('token');
    }
}
