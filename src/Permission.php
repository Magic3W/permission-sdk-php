<?php namespace magic3w\permission\sdk;

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
		$request = request(sprintf('%s/grant/eval.json?%s', $this->endpoint, http_build_query(['signature' => strval($this->sso->makeSignature($this->appid))])));
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
