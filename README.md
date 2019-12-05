# think-jwt
只支持 `thinkphp 6.0`
### 安装
```sh
$ composer require xiaodi/think-jwt:dev-master
```

### 使用
1. 命令生成签名key
```sh
$ php think jwt:sign_key
```

2. 配置
`config/jwt.php`

* `sso` 是否单点登录
* `sso_key` 用户唯一标识(多点登录 设置失效)
* `signer_key` 密钥
* `not_before` 时间前不能使用 默认生成后直接使用
* `expires_at` Token有效期（秒）
* `signer` 加密算法
* `inject_user` 是否注入用户模型
* `user` 用户模型

3. Token 生成
```php
use xiaodi\Jwt;

public function login(Jwt $jwt)
{
    //...登录判断逻辑

    $token = $jwt->getToken();
}
```

4. Token 验证(手动)
```php
use xiaodi\Jwt;

class User {

    public function test(Jwt $jwt)
    {
        try {
            $jwt->verify($token);
        } catch (\Exception $e) {
            var_dump($e->getMessage());
        }
    }
}

```

5. Token 验证(中间件)
```php
use xiaodi\Jwt;

use app\model\User;
use xiaodi\Middleware\Jwt;

class UserController {
    protected $middleware = [Jwt::class];

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

5. 路由验证(中间件)
`route/app.php`
`allowCrossDomain()` 允许跨域
```php
use xiaodi\Middleware\Jwt;

Route::rule('/user', 'index/user', 'GET')->allowCrossDomain()->middleware(Jwt::class);
```
