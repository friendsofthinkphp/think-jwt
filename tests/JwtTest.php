<?php

namespace xiaodi\JWTAuth\Tests;

use Lcobucci\JWT\Token;
use Mockery as m;
use think\App;
use think\Container;
use think\facade\Config;
use xiaodi\Exception\JWTException;
use xiaodi\Exception\JWTInvalidArgumentException;
use xiaodi\Exception\TokenAlreadyEexpired;
use xiaodi\JWTAuth\Blacklist;
use xiaodi\JWTAuth\Jwt;

class JwtTest extends TestCase
{
    protected function setUp()
    {
        parent::setUp();

        $this->blacklist = m::mock(Blacklist::class)->makePartial();

        $signerKey = 'tant';
        $this->customConfig = [
            'sso'          => false,
            'ssoCacheKey'  => 'jwt-auth-user',
            'ssoKey'       => 'uid',
            'signerKey'    => $signerKey,
            'notBefore'    => 0,
            'expiresAt'    => 3600,
            'signer'       => 'Lcobucci\JWT\Signer\Hmac\Sha256',
            'type'         => 'Bearer',
            'injectUser'   => false,
            'userModel'    => '',
            'hasLogged'    => 50401,
            'tokenAlready' => 50402,
        ];

        Container::setInstance($this->app);

        $this->app->shouldReceive('make')->with(App::class)->andReturn($this->app);
        $this->config = m::mock(Config::class)->makePartial();
        $this->config->shouldReceive('get')->with('jwt')->andReturn($this->customConfig);
        $this->config->shouldReceive('get')->with('cache.default', null)->andReturn('file');
        $this->config->shouldReceive('get')->with('cache.stores.file', null)->andReturn([
            // 驱动方式
            'type' => 'File',
            // 缓存保存目录
            'path' => '',
            // 缓存前缀
            'prefix' => '',
            // 缓存有效期 0表示永久缓存
            'expire' => 0,
            // 缓存标签前缀
            'tag_prefix' => 'tag:',
            // 序列化机制 例如 ['serialize', 'unserialize']
            'serialize' => [],
        ]);

        $this->app->shouldReceive('get')->with('config')->andReturn($this->config);
    }

    /**
     * 测试 配置.
     *
     * @return void
     */
    public function testGetConfig()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $this->assertEquals($this->customConfig, $jwt->getConfig());
    }

    public function testSignerKey()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $this->assertEquals($this->customConfig['signerKey'], $jwt->getSignerKey());
    }

    public function testParse()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $token = $jwt->token(['uid' => 1]);
        $token = $jwt->parse((string) $token);

        $flag = $token instanceof Token;
        $this->assertEquals(true, $flag);

        $this->expectException(JWTInvalidArgumentException::class);
        $jwt->parse('xxx');
    }

    public function testCode()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $this->assertEquals(50401, $jwt->getHasLoggedCode());
        $this->assertEquals(50402, $jwt->getAlreadyCode());
    }

    public function testToken()
    {
        $jwt = new Jwt($this->app, $this->blacklist);

        $uid = 1;
        $token = $jwt->token(['uid' => $uid]);
        $flag = $token instanceof Token;
        $this->assertEquals(true, $flag);
    }

    public function testVerify()
    {
        $jwt = new Jwt($this->app, $this->blacklist);

        $uid = 1;
        $token = $jwt->token(['uid' => $uid]);
        $flag = $token instanceof Token;
        $this->assertEquals(true, $flag);

        $flag = $jwt->verify((string) $token);

        $this->assertEquals(true, $flag);
    }

    public function testSSOVerify()
    {
        $jwt = new Jwt($this->app, $this->blacklist);

        $uid = 1;
        $jwt->setSSO(true);
        $jwt->setSSOKey('uid');
        $token = $jwt->token(['uid' => $uid]);

        $flag = $jwt->verify((string) $token);

        $this->assertEquals(true, $flag);
    }

    public function testTokenSignerNotMatch()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $token = $jwt->token(['uid' => 1]);
        $jwt->setSignerKey('xxx');
        $this->expectException(JWTException::class);
        $jwt->verify((string) $token);
    }

    public function testGetSigner()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $jwt->setSigner('');
        $this->expectException(JWTInvalidArgumentException::class);
        $jwt->token(['uid' => 1]);
    }

    public function testInvalidSsoKey()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $jwt->setSSO(true);
        $jwt->setSSOKey('');
        $this->expectException(JWTInvalidArgumentException::class);
        $jwt->token(['uids' => 1234]);
    }

    public function testInvalidExceptionSsoKey()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $jwt->setSSO(true);
        $jwt->setSSOKey('uids');
        $this->expectException(JWTInvalidArgumentException::class);
        $jwt->token(['uid' => 1234]);
    }

    public function testSso()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $jwt->setSSO(true);
        $jwt->setSSOKey('uid');
        $jwt->token(['uid' => 1234]);
    }

    public function testRefresh()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $token = $jwt->token(['uid' => 1234]);
        $token = $jwt->refresh($token);

        $this->assertEquals(true, $token instanceof Token);
    }

    public function testTokenAlreadyEexpired()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $jwt->setExpiresAt(-1);
        $token = $jwt->token(['uid' => 1234]);
        $this->expectException(TokenAlreadyEexpired::class);
        $jwt->verify((string) $token);
    }

    public function testTokenNotBefore()
    {
        $jwt = new Jwt($this->app, $this->blacklist);
        $jwt->setNotBefore(10);
        $token = $jwt->token(['uid' => 1234]);
        $this->expectException(JWTException::class);
        $jwt->verify((string) $token);
    }
}
