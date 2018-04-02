<?php

namespace Rarst\ReleaseBelt\Provider;

use Pimple\Container;
use Pimple\ServiceProviderInterface;
use Silex\Api\BootableProviderInterface;
use Silex\Application;
use Symfony\Component\Finder\Finder;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestMatcher;

class AuthenticationProvider implements ServiceProviderInterface, BootableProviderInterface
{
    public function register(Container $app)
    {
        $app['security.firewalls'] = [];
    }

    public function boot(Application $app)
    {
        $firewalls = [];
        $userHashes = $this->getUserHashes($app);
        $ipWhitelist = array_keys($app['ips']);

        if (!empty($ipWhitelist)) {
            $firewalls['composer_ip_whitelist'] = [
                'pattern' => new RequestMatcher('^.*$', null, null, $ipWhitelist),
            ];
        }

        if (!empty($userHashes)) {
            $firewalls['composer'] = [
                'pattern' => '^.*$',
                'http'    => true,
                'users'   => $userHashes,
            ];
        }

        if (!empty($firewalls)) {
            $app['security.firewalls'] = $firewalls;

            $app->extend('finder', function (Finder $finder, Application $app) {

                /** @var array[][] $users */
                $users = $app['users'];
                $ips = $app['ips'];
                /** @var Request $request */
                $request = $app['request_stack']->getCurrentRequest();
                $user    = $request->getUser();
                $ip      = $request->getClientIp();

                if (empty($user)) {
                    $haystack = $ips;
                    $needle = $ip;
                } else {
                    $haystack = $users;
                    $needle = $user;
                }

                return $this->applyPermissions($finder, $this->getPermissions($haystack, $needle));
            });
        }
    }

    protected function getUserHashes(Application $app)
    {
        $users = [];

        if ( ! empty($app['http.users'])) {
            trigger_error('`http.users` option is deprecated in favor of `users`.', E_USER_DEPRECATED);

            foreach ($app['http.users'] as $login => $hash) {
                $users[$login] = ['ROLE_COMPOSER', $hash];
            }
        }

        foreach ($app['users'] as $login => $data) {
            $users[$login] = ['ROLE_COMPOSER', $data['hash']];
        }

        return $users;
    }

    protected function getPermissions(array $haystack, $needle)
    {
        return [
            // TODO use ?? when bumped requirements to PHP 7.
            'allow'    => empty($haystack[$needle]['allow']) ? [] : $haystack[$needle]['allow'],
            'disallow' => empty($haystack[$needle]['disallow']) ? [] : $haystack[$needle]['disallow'],
        ];
    }

    protected function applyPermissions(Finder $finder, array $permissions)
    {
        foreach ($permissions['allow'] as $path) {
            $finder->path($path);
        }

        foreach ($permissions['disallow'] as $path) {
            $finder->notPath($path);
        }

        return $finder;
    }
}
