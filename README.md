# think-jwt

[![Build Status](https://travis-ci.org/edenleung/think-jwt.svg?branch=master)](https://travis-ci.org/edenleung/think-jwt)
[![Scrutinizer Code Quality](https://scrutinizer-ci.com/g/edenleung/think-jwt/badges/quality-score.png?b=master)](https://scrutinizer-ci.com/g/edenleung/think-jwt/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/edenleung/think-jwt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/edenleung/think-jwt/?branch=master)
[![Code Coverage](https://scrutinizer-ci.com/g/edenleung/think-jwt/badges/coverage.png?b=master)](https://scrutinizer-ci.com/g/edenleung/think-jwt/?branch=master)

只支持 `thinkphp 6.0`
### 安装
```sh
$ composer require xiaodi/think-jwt
```

### 使用
1. 命令生成签名key
```sh
$ php think jwt:make
```

2. 配置
`config/jwt.php`

* `sso` 是否单点登录
* `ssoCacheKey` 缓存前缀
* `ssoKey` 用户唯一标识(多点登录 设置失效)
* `signerKey` 密钥
* `notBefore` 时间前不能使用 默认生成后直接使用
* `expiresAt` Token有效期（秒）
* `signer` 加密算法
* `type`  获取 Token 途径
* `injectUser` 是否注入用户模型
* `userModel` 用户模型
* `hasLogged` 开启单点登录时，多点登录抛异常code = 50401
* `tokenAlready` Token过期抛异常code = 50402

`xiaodi\Exception\HasLoggedException`, `xiaodi\Exception\TokenAlreadyEexpired`
以上两个异常都会抛一个HTTP异常 StatusCode = 401

3. Token 生成
```php
use xiaodi\Facade\Jwt;

public function login()
{
    //...登录判断逻辑

    return json([
        'token' => Jwt::token(['uid' => 1]),
        'token_type' => Jwt::type(),
        'expires_in' => Jwt::ttl()
    ]);
}
```

4. Token 验证(手动)
```php
use xiaodi\Facade\Jwt;
use xiaodi\Exception\HasLoggedException;
use xiaodi\Exception\TokenAlreadyEexpired;

class User {

    public function test()
    {
        try {
            Jwt::verify($token);
        } catch (HasLoggedException $e) {
            // 已在其它终端登录
        } catch (TokenAlreadyEexpired $e) {
            // Token已过期
        }
        
        // 验证成功
        // 如 开启用户注入功能 可获取当前用户信息
        dump(Jwt::user());
    }
}

```

5. Token 验证(中间件)
```php
use xiaodi\Jwt;

use app\model\User;

class UserController {
    protected $middleware = ['JwtMiddleware'];

    public function test(Jwt $jwt)
    {
        var_dump($jwt->getClaims());
    }

    // 开启用户模型注入
    public function user(User $user)
    {
        var_dump($user->name);
    }
}

```

6. 自动获取验证

支持以下方式自动获取

* `Bearer`
* `Cookie`
* `Url`

赋值方式

类型 | 途径 | 标识 |
:-: | :-: | :-: | 
Bearer | Authorization | Bearer |
Cookie | Cookie| token |
Url | Request | token |

```php
# config/jwt.php

<?php

return [

    // ...其它配置
    'type' => 'Bearer',
    
    // 'type' => 'Cookie',
    // 'type' => 'Url',
];
```

```php
# UserController.php

use xiaodi\Facade\Jwt;

class User
{
    public function index()
    {
        // 自动获取并验证
        try {
            Jwt::verify();
        } catch (HasLoggedException $e) {
            // 已在其它终端登录
        } catch (TokenAlreadyEexpired $e) {
            // Token已过期
        }
        
        $uid = Jwt::userId();
    }

}
```
