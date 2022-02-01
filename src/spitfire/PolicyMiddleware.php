<?php namespace permission\policy;

use auth\SSOCache;
use auth\Token;
use permission\Permission;
use spitfire\cache\MemcachedAdapter;
use spitfire\core\Context;
use spitfire\core\ContextInterface;
use spitfire\core\Environment;
use spitfire\core\Response;
use spitfire\exceptions\PublicException;
use spitfire\io\session\Session;
use spitfire\Model;
use spitfire\mvc\middleware\MiddlewareInterface;

class PolicyMiddleware implements MiddlewareInterface
{
	
	public function after(ContextInterface $context, Response $response = null)
	{
	}
	
	public function before(ContextInterface $context)
	{
		if (!($context instanceof Context)) {
			return;
		}
		
		$session = Session::getInstance();
		$cache   = new MemcachedAdapter();
		$cache->setTimeout(120);
		
		/*
		 * If anarchy is enabled, it means that the application will not perform any
		 * policy checks and immediately proceed to process the request.
		 */
		if (isset($context->annotations['anarchy'])) {
			return;
		}
		
		/*
		 * The idea behind policy is that the application can determine whether a
		 * user has the required privileges to perform a certain operation.
		 */
		$sso        = new SSOCache(Environment::get('SSO'));
		$permission = new Permission(Environment::get('permission'), $sso);
		
		$permission->namespace(sprintf('app%s', $sso->getAppId()));
		
		
		$token = isset($_GET['token']) ? $sso->makeToken($_GET['token']) : $session->getUser();
		
		/*
		 * Set the user and authapp for the context we're in.
		 */
		$user = null;
		$authapp = isset($_GET['signature']) ? $sso->authApp($_GET['signature']) : null;
		
		if ($token && $token instanceof Token) {
			/**
			 * Since the token is set, we will attempt to extract the user from the token.
			 */
			$user  = $cache->get('vg_token_' . $token->getId(), function () use ($token) {
				return $token->isAuthenticated() ? $token->getTokenInfo()->user : null;
			});
			
			$authapp = $user ? $cache->get('vg_token_app_' . $token->getId(), function () use ($token) {
				return $token->getTokenInfo()->app->id;
			}) : null;
		}
		
		
		
		$controller = $context->controller;
		$uri = $context->app->getControllerLocator()->getControllerURI($controller);
		$policyclassname = 'policy\\' . implode('\\', $uri) . 'Policy';
		
		$resources = [];
		
		$identities = array_filter([
			sprintf('@%s', $user->id),
			$authapp? sprintf('~%s', $authapp) : null
		]);
		
		if (class_exists($policyclassname)) {
			$policy = new $policyclassname();
			if (is_callable([$policy, $context->action . 'Resources'])) {
				$resources = array_merge($resources, $policy->{$context->action . 'Resources'}(...$context->object));
			}
			if (is_callable([$policy, $context->action . 'Identities'])) {
				$resources = array_merge($resources, $policy->{$context->action . 'Identities'}(...$context->object));
			}
		}
		
		$annotations = (array)$context->annotations['policy'];
		
		foreach ($annotations as $annotation) {
			list($name, $fqn) = explode(' ', $annotation);
			
			foreach ($context->object as $k => $v) {
				$fqn = str_replace('$' . $k, $v instanceof Model? implode(':', $v->getPrimaryData()) : $v, $fqn);
			}
			
			$resources[$name] = $fqn;
		}
		
		$permissions = $permission->access($resources, $identities);
		$enforce  = array_map(function ($e) use ($resources) {
			return $resources[$e];
		}, (array)$context->annotations['policy-enforce']);
		
		
		if (!empty($context->annotations['policy-enforce']) && !$permissions->slice($enforce)->pesimistic()) {
			throw new PublicException('Failed to meet policy requirements', 401);
		}
		
		$context->controller->resources = $resources;
		$context->controller->permissions = $permissions;
		
		$context->view->set('resources', $resources);
		$context->view->set('permissions', $permissions);
	}
}
