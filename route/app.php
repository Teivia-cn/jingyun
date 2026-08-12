<?php

use think\facade\Route;

Route::get('/', 'index/index');
Route::get('docs/unified-management-api', 'DocumentationController/unifiedManagementApi');

// Anonymous authentication endpoints. Every other API endpoint is protected
// by app\middleware\ApiAuthorization after SessionInit has run.
Route::post('api/auth/login', 'Api.AuthController/login');
Route::get('api/auth/status', 'Api.AuthController/status');
Route::post('api/auth/logout', 'Api.AuthController/logout');
Route::get('api/auth/me', 'Api.AuthController/me');

Route::get('api/dashboard', 'Api.DashboardController/index');
Route::get('api/profile', 'Api.ProfileController/show');
Route::put('api/profile/password', 'Api.ProfileController/updatePassword');
Route::get('api/settings', 'Api.SettingsController/show');
Route::get('api/settings/branding', 'Api.SettingsController/branding');
Route::put('api/settings/branding', 'Api.SettingsController/updateBranding');
Route::put('api/settings/smtp', 'Api.SettingsController/updateSmtp');
Route::post('api/settings/smtp/test', 'Api.SettingsController/testSmtp');
Route::get('api/api-keys', 'Api.ApiKeyController/index');
Route::post('api/api-keys', 'Api.ApiKeyController/store');
Route::delete('api/api-keys/:id', 'Api.ApiKeyController/revoke')->pattern(['id' => '\\d+']);
Route::get('api/notifications', 'Api.NotificationController/index');

// Catalog routes consumed by the account-management UI.
Route::get('api/providers', 'Api.ProviderController/index');
Route::get('api/providers/:slug/operations', 'Api.ProviderController/operations');
Route::get('api/providers/:slug', 'Api.ProviderController/show');

// Account and inventory management. Credentials are accepted only by account
// create/update and are encrypted before persistence.
Route::get('api/accounts', 'Api.AccountController/index');
Route::post('api/accounts', 'Api.AccountController/store');
Route::get('api/accounts/:id', 'Api.AccountController/show')->pattern(['id' => '\\d+']);
Route::put('api/accounts/:id', 'Api.AccountController/update')->pattern(['id' => '\\d+']);
Route::delete('api/accounts/:id', 'Api.AccountController/destroy')->pattern(['id' => '\\d+']);

Route::get('api/resources', 'Api.ResourceController/index');
Route::post('api/resources', 'Api.ResourceController/store');
Route::get('api/resources/:id', 'Api.ResourceController/show')->pattern(['id' => '\\d+']);
Route::put('api/resources/:id', 'Api.ResourceController/update')->pattern(['id' => '\\d+']);
Route::delete('api/resources/:id', 'Api.ResourceController/destroy')->pattern(['id' => '\\d+']);
Route::get('api/resources/:id/billing-portal', 'Api.ResourceController/billingPortal')->pattern(['id' => '\\d+']);
Route::get('api/resources/:id/actions', 'Api.ResourceController/actions')->pattern(['id' => '\\d+']);
Route::post('api/resources/:id/actions', 'Api.ResourceController/executeAction')->pattern(['id' => '\\d+']);

// Sync execution is asynchronous. A queue worker transitions queued jobs to
// running/completed/failed; the HTTP request itself never invokes a provider API.
Route::get('api/sync-jobs', 'Api.SyncController/index');
Route::get('api/sync-jobs/:id', 'Api.SyncController/show')->pattern(['id' => '\\d+']);
Route::post('api/sync-jobs', 'Api.SyncController/trigger');
Route::post('api/accounts/:accountId/sync', 'Api.SyncController/trigger')->pattern(['accountId' => '\\d+']);

Route::get('api/audit-logs', 'Api.AuditLogController/index');

// Versioned API-key interface. It exposes normalized inventory and only the
// documented/catalogued provider operations; it never exposes credentials or
// arbitrary upstream request passthrough.
Route::get('api/v1/accounts', 'Api.AccountController/index');
Route::get('api/v1/resources', 'Api.ResourceController/index');
Route::get('api/v1/resources/:id', 'Api.ResourceController/show')->pattern(['id' => '\\d+']);
Route::get('api/v1/resources/:id/actions', 'Api.ResourceController/actions')->pattern(['id' => '\\d+']);
Route::post('api/v1/resources/:id/actions', 'Api.ResourceController/executeAction')->pattern(['id' => '\\d+']);
Route::get('api/v1/sync-jobs', 'Api.SyncController/index');
Route::post('api/v1/accounts/:accountId/sync', 'Api.SyncController/trigger')->pattern(['accountId' => '\\d+']);
