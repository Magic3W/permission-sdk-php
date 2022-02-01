<?php namespace magic3w\permission\sdk;

use spitfire\collection\Collection;

class Passport
{
	
	/**
	 *
	 * @var Collection
	 */
	private $result;
	
	/**
	 *
	 * @var string
	 */
	private $namespace;
	
	/**
	 *
	 * @param bool[] $result
	 * @param string $namespace
	 */
	public function __construct(array $result, string $namespace)
	{
		$this->result = new Collection($result);
		$this->namespace = $namespace;
	}
	
	/**
	 *
	 * @param string $name Name of the query
	 * @return boolean
	 */
	public function result($name) :? bool
	{
		return $this->result[$name];
	}
}
