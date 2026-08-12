<?php

declare(strict_types=1);

/**
 * One-time web installer for a fresh Tower Cloud deployment.
 *
 * Keep this file outside the public document root where possible. The small
 * public/install.php entrypoint only includes this file during installation.
 */

const INSTALLER_ROOT = __DIR__;

installerHeaders();

if (!is_file(INSTALLER_ROOT . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php')) {
    installerPage('安装器不可用', ['未找到 Composer 依赖。请先在项目目录执行 composer install。'], [], 503);
}
if (!extension_loaded('pdo_mysql') || !extension_loaded('openssl') || !extension_loaded('mbstring')) {
    installerPage('环境不满足要求', ['PHP 必须启用 pdo_mysql、openssl 与 mbstring 扩展。'], [], 503);
}
if (configuredInstallationHasUser()) {
    installerPage('系统已安装', ['系统已经创建管理员。安装器不能覆盖现有安装。'], [], 409);
}

$csrf = installerCsrfToken();
$defaults = installerDefaults();

if ((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    installerPage('安装塔维云资源管理系统', [], $defaults, 200, $csrf);
}

if (!hash_equals($csrf, postString('_csrf', false))) {
    installerPage('请求已拒绝', ['安装请求已过期，请刷新页面后重试。'], $defaults, 419, $csrf);
}
if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > 32768) {
    installerPage('请求已拒绝', ['提交内容过大。'], $defaults, 413, $csrf);
}

$input = installerInput($defaults);
$errors = validateInstallerInput($input);
if ($errors !== []) {
    installerPage('请检查安装信息', $errors, $input, 422, $csrf);
}

$database = null;
$databaseLock = null;
$installError = null;
$installErrorStatus = 500;

try {
    if (configuredInstallationHasUser()) {
        throw new InstallerException('此系统已经创建管理员，安装器不能覆盖已有安装。');
    }

    if ($input['create_database']) {
        // A database user supplied by a hosting panel is commonly limited to
        // its assigned schema. Do not require a server-level connection unless
        // the user explicitly asks the installer to create that schema.
        $server = mysqlPdo($input, null, true);
        $server->exec(
            'CREATE DATABASE IF NOT EXISTS `' . $input['db_name'] . '` '
            . 'CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci'
        );
    }
    $database = mysqlPdo($input, $input['db_name']);
    $databaseLock = acquireInstallerDatabaseLock($database, $input);
    if (databaseHasUser($database)) {
        throw new InstallerException('目标数据库已经包含管理员，安装器不能继续。');
    }

    runDatabaseSetup($input);

    // Do not replace .env until migrations and the catalog have completed.
    // This keeps a failed schema initialization from changing an existing
    // configuration file, while administrator creation still uses PDO only.
    $environment = installerEnvironment($input);
    writeEnvironmentFile($environment, $input['replace_existing_env']);

    if (databaseHasUser($database)) {
        throw new InstallerException('目标数据库已经完成初始化，安装器不能继续。');
    }
    createAdministrator($database, $input);

    clearInstallerCsrfCookie();
} catch (InstallerException $exception) {
    $installError = $exception->getMessage();
    $installErrorStatus = 422;
} catch (Throwable) {
    // Do not expose database hosts, credentials, paths, or driver errors.
    $installError = '无法完成数据库初始化。请检查数据库权限、网络连通性和 PHP 扩展后重试。';
} finally {
    if ($database instanceof PDO && is_string($databaseLock)) {
        releaseInstallerDatabaseLock($database, $databaseLock);
    }
}

if (is_string($installError)) {
    installerPage('安装未完成', [$installError], $input, $installErrorStatus, $csrf);
}

installerSuccessPage();

/** @return array<string, string|bool> */
function installerDefaults(): array
{
    $scheme = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
    $host = (string) ($_SERVER['HTTP_HOST'] ?? '');

    return [
        'app_origin' => $host === '' ? '' : $scheme . '://' . $host,
        // Hosting panels often grant a local database user to `localhost`
        // rather than to the TCP loopback address `127.0.0.1`.
        'db_host' => 'localhost',
        'db_port' => '3306',
        'db_name' => 'jingyun',
        'db_user' => '',
        'db_password' => '',
        'create_database' => false,
        'admin_username' => '',
        'admin_email' => '',
        'admin_password' => '',
        'admin_password_confirmation' => '',
        'replace_existing_env' => false,
    ];
}

/** @param array<string, string|bool> $defaults @return array<string, string|bool> */
function installerInput(array $defaults): array
{
    $input = $defaults;
    foreach (['app_origin', 'db_host', 'db_port', 'db_name', 'db_user', 'db_password', 'admin_username', 'admin_email', 'admin_password', 'admin_password_confirmation'] as $field) {
        $input[$field] = postString($field, false);
    }
    $input['create_database'] = isset($_POST['create_database']);
    $input['replace_existing_env'] = isset($_POST['replace_existing_env']);

    return $input;
}

/** @param array<string, string|bool> $input @return list<string> */
function validateInstallerInput(array $input): array
{
    $errors = [];
    $origin = (string) $input['app_origin'];
    if ($origin !== '' && !validOrigin($origin)) {
        $errors[] = '网站地址必须是完整的 HTTP 或 HTTPS 来源地址，且不能包含路径、账号或查询参数。';
    }
    if (!validDatabaseHost((string) $input['db_host'])) {
        $errors[] = 'MySQL 主机名或 IP 地址无效。';
    }
    if (preg_match('/\A\d{1,5}\z/', (string) $input['db_port']) !== 1 || (int) $input['db_port'] < 1 || (int) $input['db_port'] > 65535) {
        $errors[] = 'MySQL 端口必须在 1 到 65535 之间。';
    }
    if (preg_match('/\A[A-Za-z0-9_]{1,64}\z/', (string) $input['db_name']) !== 1) {
        $errors[] = '数据库名只能包含 1 至 64 位字母、数字或下划线。';
    }
    if (!validShortSecret((string) $input['db_user'], 128) || !validShortSecret((string) $input['db_password'], 1024, true)) {
        $errors[] = 'MySQL 用户名或密码包含不允许的控制字符，或长度超限。';
    }

    $username = (string) $input['admin_username'];
    if (preg_match('/\A[A-Za-z0-9][A-Za-z0-9_.-]{2,63}\z/', $username) !== 1) {
        $errors[] = '管理员用户名必须为 3 至 64 位字母、数字、点、下划线或连字符。';
    }
    $email = (string) $input['admin_email'];
    if (mb_strlen($email) > 254 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
        $errors[] = '管理员邮箱格式无效。';
    }
    $password = (string) $input['admin_password'];
    if (strlen($password) < 12 || strlen($password) > 1024) {
        $errors[] = '管理员密码长度必须为 12 至 1024 个字符。';
    }
    if (!hash_equals($password, (string) $input['admin_password_confirmation'])) {
        $errors[] = '两次输入的管理员密码不一致。';
    }
    if (is_file(INSTALLER_ROOT . DIRECTORY_SEPARATOR . '.env') && !$input['replace_existing_env']) {
        $errors[] = '检测到已有 .env。仅当确认这是未初始化环境时，才允许备份并替换该文件。';
    }

    return $errors;
}

/** @param array<string, string|bool> $input */
function mysqlPdo(array $input, ?string $database, bool $serverConnection = false): PDO
{
    $dsn = 'mysql:host=' . $input['db_host'] . ';port=' . $input['db_port']
        . ($database === null ? '' : ';dbname=' . $database) . ';charset=utf8mb4';

    try {
        return new PDO($dsn, (string) $input['db_user'], (string) $input['db_password'], [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    } catch (PDOException $exception) {
        throw new InstallerException(mysqlConnectionErrorMessage($exception, $database, $serverConnection), 0, $exception);
    }
}

function mysqlConnectionErrorMessage(PDOException $exception, ?string $database, bool $serverConnection): string
{
    $driverCode = $exception->errorInfo[1] ?? null;
    $driverCode = is_int($driverCode) ? $driverCode : (is_numeric($driverCode) ? (int) $driverCode : 0);

    return match ($driverCode) {
        1044 => 'MySQL 账号没有访问目标数据库的权限。请在数据库管理面板为该账号授权后重试。',
        1045 => 'MySQL 用户名、密码或主机授权不正确。请检查账号密码；本机数据库账号可尝试使用 localhost 作为主机。',
        1049 => $database === null
            ? 'MySQL 服务连接成功，但未指定可用的数据库。请填写数据库名称后重试。'
            : '目标数据库不存在。请先在数据库管理面板创建它，或勾选“尝试创建数据库”。',
        1040, 1203 => 'MySQL 当前连接数已满。请稍后重试或提高数据库连接上限。',
        2002, 2003, 2006, 2013 => '无法连接到 MySQL 服务。请检查主机、端口、MySQL 服务状态和网络访问规则。',
        2054 => '当前 PHP 的 MySQL 驱动不支持该数据库账号使用的认证方式。请升级 PHP MySQL 驱动或调整数据库账号认证方式。',
        default => $serverConnection
            ? '无法以当前 MySQL 账号连接服务端来创建数据库。请检查账号权限；若数据库已存在，请取消“尝试创建数据库”。'
            : '无法连接到目标 MySQL 数据库。请检查主机、端口、数据库名称、账号权限和网络访问规则。',
    };
}

function databaseHasUser(PDO $database): bool
{
    try {
        $table = $database->query("SHOW TABLES LIKE 'users'");
        if ($table === false || $table->fetchColumn() === false) {
            return false;
        }

        return $database->query('SELECT 1 FROM `users` LIMIT 1')->fetchColumn() !== false;
    } catch (PDOException $exception) {
        throw new InstallerException('无法检查目标数据库的安装状态。', 0, $exception);
    }
}

/** @param array<string, string|bool> $input */
function acquireInstallerDatabaseLock(PDO $database, array $input): string
{
    // Named locks are scoped to one MySQL server, so the database name is
    // sufficient and remains stable when the same server is addressed by a
    // hostname, IPv4 address, or IPv6 address.
    $name = 'towercloud.install.' . substr(hash('sha256', (string) $input['db_name']), 0, 40);

    try {
        $statement = $database->prepare('SELECT GET_LOCK(:name, 0)');
        $statement->execute(['name' => $name]);
        if ((int) $statement->fetchColumn() !== 1) {
            throw new InstallerException('另一个安装请求正在执行，请稍候再刷新页面。');
        }
    } catch (InstallerException $exception) {
        throw $exception;
    } catch (PDOException $exception) {
        throw new InstallerException('无法获取数据库安装锁。请确认 MySQL 服务可用后重试。', 0, $exception);
    }

    return $name;
}

function releaseInstallerDatabaseLock(PDO $database, string $name): void
{
    try {
        $statement = $database->prepare('SELECT RELEASE_LOCK(:name)');
        $statement->execute(['name' => $name]);
    } catch (PDOException) {
        // Closing the PDO connection also releases a MySQL named lock.
    }
}

function configuredInstallationHasUser(): bool
{
    $envPath = INSTALLER_ROOT . DIRECTORY_SEPARATOR . '.env';
    if (!is_file($envPath)) {
        return false;
    }
    $config = @parse_ini_file($envPath, false, INI_SCANNER_RAW);
    if (!is_array($config)
        || !isset($config['DB_HOST'], $config['DB_PORT'], $config['DB_NAME'])) {
        return false;
    }
    try {
        $dbUser = $config['DB_USER'] ?? null;
        $dbPassword = $config['DB_PASS'] ?? null;
        if (!is_string($dbUser) || !is_string($dbPassword)) {
            return false;
        }
        $input = [
            'db_host' => (string) $config['DB_HOST'],
            'db_port' => (string) $config['DB_PORT'],
            'db_name' => (string) $config['DB_NAME'],
            'db_user' => $dbUser,
            'db_password' => $dbPassword,
        ];

        return databaseHasUser(mysqlPdo($input, $input['db_name']));
    } catch (Throwable) {
        // An unavailable old database is not proof of a completed installation.
        return false;
    }
}

/** @param array<string, string|bool> $input */
function runDatabaseSetup(array $input): void
{
    require_once INSTALLER_ROOT . DIRECTORY_SEPARATOR . 'vendor' . DIRECTORY_SEPARATOR . 'autoload.php';
    $app = new \think\App(INSTALLER_ROOT);
    $app->initialize();

    // A stale optimized config must not override the database just submitted.
    $databaseConfig = (array) $app->config->get('database', []);
    $databaseConfig['default'] = 'mysql';
    $databaseConfig['connections']['mysql'] = array_replace(
        (array) ($databaseConfig['connections']['mysql'] ?? []),
        [
            'type' => 'mysql',
            'hostname' => (string) $input['db_host'],
            'database' => (string) $input['db_name'],
            'username' => (string) $input['db_user'],
            'password' => (string) $input['db_password'],
            'hostport' => (string) $input['db_port'],
            'charset' => 'utf8mb4',
            'prefix' => '',
        ]
    );
    $app->config->set($databaseConfig, 'database');

    try {
        $app->console->call('migrate:run', [], 'buffer')->fetch();
        $app->console->call('seed:run', ['--seed=ProviderCatalogSeeder'], 'buffer')->fetch();
    } catch (Throwable $exception) {
        throw new InstallerException('数据库结构或服务商目录初始化失败。请确认数据库账号具有建表、索引和外键权限。', 0, $exception);
    }
}

/** @param array<string, string|bool> $input */
function createAdministrator(PDO $database, array $input): void
{
    $passwordHash = password_hash((string) $input['admin_password'], PASSWORD_DEFAULT);
    if (!is_string($passwordHash) || $passwordHash === '') {
        throw new InstallerException('无法安全处理管理员密码。');
    }

    try {
        $database->beginTransaction();
        if ($database->query('SELECT `id` FROM `users` LIMIT 1 FOR UPDATE')->fetchColumn() !== false) {
            $database->rollBack();
            throw new InstallerException('目标数据库已经完成初始化，安装器不能继续。');
        }
        $now = date('Y-m-d H:i:s');
        $statement = $database->prepare(
            'INSERT INTO `users` (`username`, `email`, `password_hash`, `display_name`, `avatar_url`, `role`, `status`, `last_login_at`, `created_at`, `updated_at`) '
            . 'VALUES (:username, :email, :password_hash, :display_name, NULL, :role, 1, NULL, :created_at, :updated_at)'
        );
        $statement->execute([
            'username' => (string) $input['admin_username'],
            'email' => mb_strtolower((string) $input['admin_email']),
            'password_hash' => $passwordHash,
            'display_name' => (string) $input['admin_username'],
            'role' => 'admin',
            'created_at' => $now,
            'updated_at' => $now,
        ]);
        $database->commit();
    } catch (InstallerException $exception) {
        throw $exception;
    } catch (Throwable $exception) {
        if ($database->inTransaction()) {
            $database->rollBack();
        }
        throw new InstallerException('无法创建管理员。请使用不同的用户名或邮箱后重试。', 0, $exception);
    }
}

/** @param array<string, string|bool> $input @return array<string, string> */
function installerEnvironment(array $input): array
{
    $origin = (string) $input['app_origin'];
    $secureCookie = $origin === '' || str_starts_with($origin, 'https://');

    return [
        'APP_DEBUG' => 'false',
        'DEFAULT_LANG' => 'zh-cn',
        'APP_ORIGIN' => $origin,
        'DB_DRIVER' => 'mysql',
        'DB_TYPE' => 'mysql',
        'DB_HOST' => (string) $input['db_host'],
        'DB_PORT' => (string) $input['db_port'],
        'DB_NAME' => (string) $input['db_name'],
        'DB_USER' => (string) $input['db_user'],
        'DB_PASS' => (string) $input['db_password'],
        'DB_CHARSET' => 'utf8mb4',
        'DB_PREFIX' => '',
        'CREDENTIAL_ENCRYPTION_KEY' => base64_encode(random_bytes(32)),
        'CREDENTIAL_ENCRYPTION_KEY_VERSION' => 'v1',
        'SESSION_SECURE_COOKIE' => $secureCookie ? 'true' : 'false',
        'SESSION_NAME' => $secureCookie ? '__Host-jingyun_session' : 'jingyun_session',
        'SESSION_EXPIRE' => '7200',
        'SESSION_DATABASE_TABLE' => 'sessions',
    ];
}

/** @param array<string, string> $environment */
function writeEnvironmentFile(array $environment, bool $replaceExisting): void
{
    $path = INSTALLER_ROOT . DIRECTORY_SEPARATOR . '.env';
    if (is_file($path)) {
        if (!$replaceExisting) {
            throw new InstallerException('检测到已有 .env，安装器不会在未确认的情况下覆盖配置。');
        }
        $backup = INSTALLER_ROOT . DIRECTORY_SEPARATOR . '.env.backup.' . gmdate('YmdHis') . '.' . bin2hex(random_bytes(4));
        if (!copy($path, $backup)) {
            throw new InstallerException('无法备份已有 .env，安装已停止。');
        }
        @chmod($backup, 0600);
    }

    $lines = ['# Generated by install.php. Keep this file private and out of Git.'];
    foreach ($environment as $key => $value) {
        $lines[] = $key . ' = "' . iniEscape($value) . '"';
    }
    $content = implode("\n", $lines) . "\n";
    $temporary = $path . '.tmp.' . bin2hex(random_bytes(6));
    if (file_put_contents($temporary, $content, LOCK_EX) === false) {
        throw new InstallerException('无法写入环境配置文件。');
    }
    @chmod($temporary, 0600);
    if (!rename($temporary, $path)) {
        @unlink($temporary);
        throw new InstallerException('无法启用环境配置文件。');
    }
    @chmod($path, 0600);
}

function iniEscape(string $value): string
{
    if (preg_match('/[\x00-\x1F\x7F]/', $value) === 1) {
        throw new InstallerException('配置值包含不允许的控制字符。');
    }

    return str_replace(['\\', '"'], ['\\\\', '\\"'], $value);
}

function validOrigin(string $origin): bool
{
    $parts = parse_url($origin);
    if (!is_array($parts) || !in_array($parts['scheme'] ?? '', ['http', 'https'], true)
        || !isset($parts['host']) || isset($parts['user'], $parts['pass'], $parts['query'], $parts['fragment'])) {
        return false;
    }

    return !isset($parts['path']) || $parts['path'] === '/' || $parts['path'] === '';
}

function validDatabaseHost(string $host): bool
{
    if ($host === '' || strlen($host) > 253 || preg_match('/[\x00-\x20\x7F\\/@]/', $host) === 1) {
        return false;
    }
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
        return true;
    }

    if (str_contains($host, ':')) {
        return false;
    }

    return preg_match('/\A(?=.{1,253}\z)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\z/', $host) === 1;
}

function validShortSecret(string $value, int $maxLength, bool $allowEmpty = false): bool
{
    return ($allowEmpty || $value !== '') && strlen($value) <= $maxLength && preg_match('/[\x00-\x1F\x7F]/', $value) !== 1;
}

function postString(string $key, bool $trim = true): string
{
    $value = $_POST[$key] ?? '';
    if (!is_string($value)) {
        return '';
    }

    return $trim ? trim($value) : $value;
}

function installerCsrfToken(): string
{
    $name = 'towercloud_install_csrf';
    $token = $_COOKIE[$name] ?? '';
    if (is_string($token) && preg_match('/\A[a-f0-9]{64}\z/', $token) === 1) {
        return $token;
    }

    $token = bin2hex(random_bytes(32));
    setcookie($name, $token, installerCsrfCookieOptions(time() + 1800));
    $_COOKIE[$name] = $token;

    return $token;
}

function clearInstallerCsrfCookie(): void
{
    $name = 'towercloud_install_csrf';
    setcookie($name, '', installerCsrfCookieOptions(time() - 3600));
    unset($_COOKIE[$name]);
}

/** @return array<string, bool|int|string> */
function installerCsrfCookieOptions(int $expires): array
{
    return [
        'expires' => $expires,
        'path' => '/',
        'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Strict',
    ];
}

function installerHeaders(): void
{
    header('Content-Type: text/html; charset=utf-8');
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Pragma: no-cache');
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header("Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'");
}

/** @param list<string> $errors @param array<string, string|bool> $values */
function installerPage(string $title, array $errors, array $values, int $status, string $csrf = ''): void
{
    http_response_code($status);
    $errorHtml = $errors === [] ? '' : '<div class="notice error"><strong>请处理以下问题</strong><ul><li>' . implode('</li><li>', array_map('e', $errors)) . '</li></ul></div>';
    $form = $csrf === '' ? '' : installerForm($values, $csrf);
    echo '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>' . e($title) . '</title><style>'
        . '*{box-sizing:border-box}body{margin:0;background:#f5f5f7;color:#1d1d1f;font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{width:min(760px,calc(100% - 32px));margin:44px auto 80px}.brand{font-weight:700;color:#0071e3;margin-bottom:12px}h1{font-size:30px;margin:0 0 10px;letter-spacing:0}p{line-height:1.65;color:#515154}.panel{background:#fff;border:1px solid #d2d2d7;border-radius:14px;padding:26px;box-shadow:0 10px 28px rgba(0,0,0,.06)}.section{margin-top:24px;padding-top:4px}.section h2{font-size:17px;margin:0 0 14px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.full{grid-column:1/-1}label{display:block;font-size:13px;font-weight:600;margin:0 0 6px}input{width:100%;height:42px;border:1px solid #c7c7cc;border-radius:8px;padding:0 11px;font:inherit;color:inherit;background:#fff}input:focus{outline:3px solid rgba(0,113,227,.22);border-color:#0071e3}.check{display:flex;align-items:flex-start;gap:9px;margin-top:14px;font-weight:400}.check input{width:16px;height:16px;margin:2px 0 0}.notice{margin:18px 0;padding:14px 16px;border-radius:9px;background:#eef6ff;color:#164b79;line-height:1.55}.notice.error{background:#fff2f2;color:#9a1f1f}.notice ul{margin:7px 0 0;padding-left:19px}button,.button{display:inline-flex;align-items:center;justify-content:center;min-height:42px;border:0;border-radius:8px;padding:0 17px;background:#0071e3;color:#fff;font:600 14px inherit;text-decoration:none;cursor:pointer}button:hover,.button:hover{background:#0077ed}.footer{font-size:12px;color:#6e6e73;margin:16px 0 0;line-height:1.6}@media(max-width:600px){.wrap{margin-top:24px}.panel{padding:20px}.grid{grid-template-columns:1fr}.full{grid-column:auto}}</style></head><body><main class="wrap"><div class="brand">塔维云资源管理系统</div><h1>' . e($title) . '</h1>' . $errorHtml . '<div class="panel">' . $form . '</div></main></body></html>';
    exit;
}

/** @param array<string, string|bool> $values */
function installerForm(array $values, string $csrf): string
{
    $existingEnv = is_file(INSTALLER_ROOT . DIRECTORY_SEPARATOR . '.env');

    return '<p>此操作仅用于全新部署：创建数据库结构、写入服务商目录并创建首位管理员。管理员记录创建后，安装器将拒绝再次初始化。</p><form method="post" autocomplete="off"><input type="hidden" name="_csrf" value="' . e($csrf) . '"><div class="section"><h2>站点</h2><div class="grid"><div class="full"><label for="app_origin">网站地址（可选）</label><input id="app_origin" name="app_origin" type="url" inputmode="url" maxlength="2048" placeholder="https://console.example.com" value="' . e((string) $values['app_origin']) . '"></div></div></div><div class="section"><h2>MySQL</h2><div class="grid"><div><label for="db_host">主机</label><input id="db_host" name="db_host" required maxlength="253" value="' . e((string) $values['db_host']) . '"></div><div><label for="db_port">端口</label><input id="db_port" name="db_port" required inputmode="numeric" maxlength="5" value="' . e((string) $values['db_port']) . '"></div><div><label for="db_name">数据库名</label><input id="db_name" name="db_name" required maxlength="64" pattern="[A-Za-z0-9_]+" value="' . e((string) $values['db_name']) . '"></div><div><label for="db_user">用户名</label><input id="db_user" name="db_user" required maxlength="128" value="' . e((string) $values['db_user']) . '"></div><div class="full"><label for="db_password">密码</label><input id="db_password" name="db_password" type="password" autocomplete="new-password" maxlength="1024"></div></div><label class="check"><input name="create_database" type="checkbox"' . checked((bool) $values['create_database']) . '>若数据库不存在，尝试创建数据库（要求该 MySQL 用户具有 CREATE 权限）</label>' . ($existingEnv ? '<label class="check"><input name="replace_existing_env" type="checkbox"' . checked((bool) $values['replace_existing_env']) . '>我确认此目录尚未初始化，并允许安装器先备份后替换已有 .env</label>' : '') . '</div><div class="section"><h2>管理员</h2><div class="grid"><div><label for="admin_username">用户名</label><input id="admin_username" name="admin_username" required autocomplete="username" minlength="3" maxlength="64" pattern="[A-Za-z0-9][A-Za-z0-9_.-]{2,63}" value="' . e((string) $values['admin_username']) . '"></div><div><label for="admin_email">邮箱</label><input id="admin_email" name="admin_email" type="email" required autocomplete="email" maxlength="254" value="' . e((string) $values['admin_email']) . '"></div><div><label for="admin_password">密码</label><input id="admin_password" name="admin_password" type="password" required autocomplete="new-password" minlength="12" maxlength="1024"></div><div><label for="admin_password_confirmation">确认密码</label><input id="admin_password_confirmation" name="admin_password_confirmation" type="password" required autocomplete="new-password" minlength="12" maxlength="1024"></div></div></div><div class="section"><button type="submit">开始安装</button><p class="footer">安装器本身不要求 runtime 可写。安装完成后，删除或限制 install.php 的访问，并确保 .env 与 runtime 不被 Web 或 Git 公开。</p></div></form>';
}

function installerSuccessPage(): void
{
    http_response_code(201);
    echo '<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>安装完成</title><style>body{margin:0;background:#f5f5f7;color:#1d1d1f;font:15px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.wrap{width:min(620px,calc(100% - 32px));margin:72px auto}.panel{background:#fff;border:1px solid #d2d2d7;border-radius:14px;padding:28px;box-shadow:0 10px 28px rgba(0,0,0,.06)}h1{font-size:29px;margin:0 0 12px}p,li{line-height:1.65;color:#515154}.button{display:inline-flex;align-items:center;justify-content:center;min-height:42px;border-radius:8px;padding:0 17px;background:#0071e3;color:#fff;font:600 14px -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;text-decoration:none}</style></head><body><main class="wrap"><div class="panel"><h1>安装完成</h1><p>数据库结构、服务商目录和管理员账号已创建。安装状态由管理员记录确认，安装器不能再次初始化。</p><ol><li>立即删除或在 Web 服务器层拒绝 <code>install.php</code> 与 <code>public/install.php</code>。</li><li>确认 <code>.env</code> 与 <code>runtime/</code> 不可被 Web 访问，且未提交到 Git。</li><li>为同步 Worker 配置计划任务后再接入服务商账号。</li></ol><a class="button" href="./">进入登录页</a></div></main></body></html>';
    exit;
}

function checked(bool $value): string
{
    return $value ? ' checked' : '';
}

function e(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

final class InstallerException extends RuntimeException
{
}
