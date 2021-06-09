<?php namespace magic3w\permission\sdk;

use Exception;
use magic3w\http\url\reflection\URLReflection;
use magic3w\phpauth\sdk\SSO;
use spitfire\io\request\Request;

class Permission
{
	
	/**
	 *
	 * @var string
	 */
	private $endpoint;
	
	/**
	 *
	 * @var string
	 */
	private $namespace;
	
	/**
	 * 
	 * @param string $endpoint
	 */
	public function __construct(string $endpoint)
	{
		$reflection = URLReflection::fromURL($endpoint);
		$protocol = $reflection->getProtocol();
		$hostname = $reflection->getServer();
		$port = $reflection->getPort();
		
		$this->endpoint  = rtrim($protocol . '://' . $hostname . ':' . $port . $reflection->getPath(), '/');
	}
	
	/**
	 * When querying a permission server, you pass an array of queries that you wish
	 * the server to analyze.
	 * 
	 * There's generally multiple queries involved since an application usually needs
	 * to check several access permissions, you always write it like an array of pairs
	 * of arrays. Something like this:
	 * 
	 * [
	 *  'read' => [
	 *      'resource1.read',
	 *      ['@id1', ':group', '&registered', true]
	 *  ],
	 *  'edit' => [
	 *      'resource1.edit',
	 *      ['@id1', ':group', false]
	 *  ]
	 * ]
	 * 
	 * You can then access it like $result->result('edit')
	 * 
	 * For performance, you should generally look into the options provided by the
	 * compile method.
	 * 
	 * @param array<string, array{string, string[]}> $query
	 * @return \magic3w\permission\sdk\Passport
	 */
	public function access($query) 
	{	
		$mapped  = array_map(function ($e) { 
			return substr($e[0], 0, 1) === '@'? $this->namespace . '.' . substr($e[0], 1) : $e[0]; 
		}, $query);
		
		$encoded = json_encode($mapped);
		
		if ($encoded === false) {
			throw new Exception('Cannot encode the query');
		}
		
		$request = new Request(sprintf('%s/grant/eval.json', $this->endpoint));
		$request->post($encoded);
		$request->header('Content-type', 'application/json');
		
		$result = $request->send()->json();
		
		return new Passport($result, $this->namespace);
	}
	
	/**
	 * 
	 * @param string $set
	 * @return $this
	 */
	public function namespace(string $set) 
	{
		$this->namespace = $set;
		return $this;
	}
}
