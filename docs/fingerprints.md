# Framework fingerprint coverage

Reviewed 2026-10-22. The embedded [catalogue](../engine/probe/frameworks.json)
covers 20 PHP framework families. They were selected for coverage and are
not the twenty most popular. The catalogue adds to the CMS, forum, hosting
and generic PHP hints.

Every family is recognised by an explicit name in `X-Powered-By`,
`X-Generator` or a generator meta tag, although the frameworks do not
necessarily set those fields. Alias boundaries are checked to reject
lookalike names.

Every family also has a namespace or class-prefix signature for diagnostics
already returned with HTTP 5xx and an exception, stack trace or fatal-error
context. The checker MUST NOT request debug endpoints or induce errors to
obtain these signals. Symfony, Illuminate, Laminas and other components can
be embedded in different applications; diagnostic evidence therefore
identifies a component family, not the entire application.

| Family | Diagnostic identifier prefix | Additional passive signals | Identifier source |
|---|---|---|---|
| Laravel | `Illuminate\` | Exact `laravel_session`, `laravel-session` cookie names | [Official source](https://raw.githubusercontent.com/laravel/framework/12.x/src/Illuminate/Database/QueryException.php) |
| Symfony | `Symfony\` | Profiler header pair | [Official source](https://raw.githubusercontent.com/symfony/http-kernel/7.3/Exception/HttpException.php) |
| CodeIgniter | `CodeIgniter\` | Exact `ci_session` cookie names | [Official source](https://raw.githubusercontent.com/codeigniter4/CodeIgniter4/develop/system/Exceptions/FrameworkException.php) |
| CakePHP | `Cake\` | Exact `CAKEPHP` cookie names | [Official source](https://raw.githubusercontent.com/cakephp/cakephp/5.x/src/Http/Exception/HttpException.php) |
| Yii | `yii\` | Paired Yii script assets | [Official source](https://raw.githubusercontent.com/yiisoft/yii2/master/framework/web/HttpException.php) |
| Nette | `Nette\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/nette/application/master/src/Application/exceptions.php) |
| Laminas | `Laminas\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/laminas/laminas-mvc/3.8.x/src/Exception/RuntimeException.php) |
| Zend Framework | `Zend\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/zendframework/zend-mvc/master/src/Exception/RuntimeException.php) |
| Phalcon | `Phalcon\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/phalcon/cphalcon/master/phalcon/Mvc/Dispatcher/Exception.zep) |
| Slim | `Slim\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/slimphp/Slim/4.x/Slim/Exception/HttpException.php) |
| FuelPHP | `Fuel\Core\` | Exact `fuelcid`, `fuelfid`, `fuelmid`, `fueldid`, `fuelrid` cookie names | [Official source](https://raw.githubusercontent.com/fuel/core/1.9/develop/classes/httpexceptions.php) |
| Kohana | `Kohana_` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/kohana/core/3.3/master/classes/Kohana/Kohana/Exception.php) |
| ThinkPHP | `think\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/top-think/framework/8.x/src/think/exception/HttpException.php) |
| Yaf | `Yaf_` | Explicit identity or diagnostic only | [Official source](https://www.php.net/manual/en/class.yaf-exception.php) |
| Spiral | `Spiral\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/spiral/framework/master/src/Http/src/Exception/ClientException.php) |
| Hyperf | `Hyperf\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/hyperf/hyperf/master/src/http-message/src/Exception/HttpException.php) |
| Mezzio | `Mezzio\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/mezzio/mezzio/3.29.x/src/Exception/RuntimeException.php) |
| PHPixie | `PHPixie\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/phpixie/orm/master/src/PHPixie/ORM/Exception.php) |
| Flight | `flight\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/flightphp/core/master/flight/core/Dispatcher.php) |
| Neos Flow | `Neos\Flow\` | Explicit identity or diagnostic only | [Official source](https://raw.githubusercontent.com/neos/flow-development-collection/9.0/Neos.Flow/Classes/Exception.php) |

The separate application catalogue adds [fifty further PHP applications](applications.md),
with a sourced coverage table and explicit limits.

## Roundcube application detection

Roundcube is recorded separately in
[applications.json](../engine/probe/applications.json), not counted among
the twenty framework families. The catalogue accepts explicit Roundcube
generator or identity declarations. It also recognises the exact
`roundcube_sessid` and `roundcube_sessauth` cookie names documented in the
[application source](https://raw.githubusercontent.com/roundcube/roundcubemail/master/program/include/rcmail.php).

Paired `program/js/app.js` and `program/js/common.js` script paths, including
paired minified variants, are a separate low-confidence indicator. Their
[renderer source](https://raw.githubusercontent.com/roundcube/roundcubemail/master/program/include/rcmail_output_html.php)
also defines the default generator. Deployments in a subdirectory are
supported. Generic `app.js`/`common.js` files elsewhere, a title alone or a
Roundcube mention in prose MUST NOT identify the application.

Roundcube versions, including the JavaScript `rcversion` value, MUST NOT be
interpreted as PHP versions. Fixtures cover cookie, generator and asset
signals, lookalikes, subdirectories, privacy and verdict integration.
GET-only verification of `webmail.evilbit.de` on 2026-10-22 identifies the
Roundcube cookie and paired minified assets. The PHP version remains
unknown, so the result is `inconclusive`.

## Signal sources and limits

The cookie, header and asset rules cite these sources, which the catalogue
records on each rule:

- Laravel cookies: [11.x](https://raw.githubusercontent.com/laravel/laravel/11.x/config/session.php) and [12.x](https://raw.githubusercontent.com/laravel/laravel/12.x/config/session.php).
- Symfony headers: [source](https://symfony.com/doc/current/profiler.html).
- CodeIgniter cookies: [source](https://raw.githubusercontent.com/codeigniter4/CodeIgniter4/develop/app/Config/Session.php).
- CakePHP cookies: [source](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/08-Fingerprint_Web_Application_Framework).
- Yii assets: [source](https://raw.githubusercontent.com/yiisoft/yii2/master/framework/assets/yii.validation.js).
- FuelPHP cookies: [source](https://raw.githubusercontent.com/fuel/core/1.9/develop/config/session.php).

Laravel cookie defaults depend on the framework version and `APP_NAME`;
custom names are not guessed. The `CAKEPHP` name is a legacy default; newer
CakePHP deployments may use the generic PHP session name. CodeIgniter and
FuelPHP cookie names are also configurable. Cookie names alone are low
confidence. Generic cookies such as `XSRF-TOKEN`, `_csrf`, `_identity`,
`session` and arbitrary names ending in `_session` MUST NOT identify a
particular framework.

Symfony profiler identification requires both a nonempty `X-Debug-Token`
and an `X-Debug-Token-Link` containing a profiler path. The link is inspected
as text and never followed. It is component evidence because applications
such as Drupal may use Symfony components. Yii asset detection requires
both `yii.js` and `yii.validation.js` script references, not their names in
prose. Browser assets can be reused or served statically, so this is a low
confidence component hint.

## Evidence and confidence

Each matched fingerprint records the technology, signal, scope, confidence,
source and observed URL, in the evidence on the page and in the API. The
source is the rule's reference and the URL is the response inspected. Raw
cookie values, debug tokens and stack-trace contents are not stored.

| Scope | Meaning | Confidence |
|---|---|---|
| `declared` | The response explicitly names the framework | medium |
| `component` | A framework component or its artifacts were observed | medium for diagnostics and the profiler; low for browser assets |
| `default_cookie` | A known default cookie name was observed | low |

Fingerprint confidence describes how strongly a technology is indicated,
not the PHP patch state. A framework version MUST NOT become a PHP version;
only the PHP version parser and the session-request observations affect the
patch assessment.

Fixtures cover all twenty diagnostic families, explicit declarations, the
production cookie, header and asset signals, provenance, privacy and
negative cases. They are synthetic responses built from the linked sources,
not live tests against twenty deployed applications.

Custom cookies, disabled diagnostics, stripped identity headers, static
exports and challenge pages can hide every framework-specific signal.
Such deployments remain undetectable through this catalogue. See
[detection.md](detection.md) for discovery and challenge handling.

`make test`, `make build` and `make test-lab` pass with the catalogue. The
lab verifies unpatched, patched and hardened PHP plus a static server;
framework coverage rests on the synthetic fixtures.
