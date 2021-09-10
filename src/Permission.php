<?php namespace magic3w\permission\sdk;

use GuzzleHttp\Client;
use magic3w\http\url\reflection\URLReflection;

class Permission
{
	
	/**
	 * 
	 * @var Client
	 */
	private $client;
	
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
		$hostname = $reflection->getHostname();
		$port = $reflection->getPort();
		
		$this->endpoint  = rtrim($protocol . '://' . $hostname . ':' . $port . $reflection->getPath(), '/');
		$this->client    = new Client(['base_uri' => $this->endpoint, 'timeout' => 5.0]);
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
		
		$encoded = json_encode($mapped, JSON_THROW_ON_ERROR);
				
		$response = $this->client->request(
			'POST',
			'grant/eval.json',
			[
				'body' => $encoded,
				'headers' => [
					'Content-type' => 'application/json',
					'Accept' => 'application/json'
				]
			]
		);
		
		return new Passport(json_decode($response->getBody(), false, JSON_THROW_ON_ERROR), $this->namespace);
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
