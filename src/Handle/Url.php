<?php

declare(strict_types=1);

namespace xiaodi\think\jwt\Handle;

class Url extends RequestToken
{
    public function handle()
    {
        return $this->app->request->get('token');
    }
}
