<?php

namespace xiaodi\JWTAuth\Tests;

use Mockery as m;
use Mockery\MockInterface;
use think\App;

abstract class TestCase extends \PHPUnit\Framework\TestCase
{
    /** @var App|MockInterface */
    protected $app;

    public function tearDown()
    {
        m::close();
    }

    protected function setUp()
    {
        $this->app = m::mock(App::class)->makePartial();
    }
}
