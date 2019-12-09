<?php

namespace xiaodi\Facade;

use think\Facade;

class Jwt extends Facade
{
    protected static function getFacadeClass()
    {
        return 'jwt';
    }
}
