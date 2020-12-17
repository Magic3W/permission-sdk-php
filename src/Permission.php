<?php namespace magic3w\permission\sdk;

use magic3w\http\url\reflection\URLReflection;
use spitfire\io\request\Request;

class Permission
{
	
	private $sso;
	private $appid;
	private $endpoint;
	
	private $namespace;
	
	
	public function __construct($endpoint, $sso) {
		$reflection = URLReflection::fromURL($endpoint);
		
		$this->endpoint  = rtrim($reflection->getProtocol() . '://' . $reflection->getServer() . ':' . $reflection->getPort() . $reflection->getPath(), '/');
		$this->appid     = $reflection->getUser();
		
		$this->sso = $sso;
	}
	
	/**
	 * 
	 * @param type $resources
	 * @param type $identities
	 * @return \permission\Passport
	 */
	public function access($resources, $identities) {
		$request = new Request(sprintf('%s/grant/eval.json', $this->endpoint));
		$request->post(json_encode(['resources' => array_map(function ($e) { return \Strings::startsWith($e, '@')? $this->namespace . '.' . substr($e, 1) : $e; }, $resources), 'identities' => $identities]));
		$request->header('Content-type', 'application/json');
		
		$result = $request->send()->json();
		
		return new Passport($result, $this->namespace);
	}
	
	public function namespace($set) {
		$this->namespace = $set;
		return $this;
	}
	
}
