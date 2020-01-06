<?php

namespace xiaodi\Exception;

use think\Exception\HttpException;

class Exception extends HttpException
{
    public function __construct(string $message, $code = 500)
    {
        parent::__construct($code, $message);
    }
}
