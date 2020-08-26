<?php namespace magic3w\permission\sdk;

class Passport
{
	
	private $result;
	private $namespace;
	
	function __construct($result, $namespace) {
		$this->result = collect((array)$result);
		$this->namespace = $namespace;
	}
	
	public function slice($which) {
		$which = (array)$which;
		$res = [];
		
		foreach ($which as $e) { 
			if (\Strings::startsWith($e, '@')) { $e = $this->namespace . '.' . substr($e, 1); }
			$res[$e] = $this->result[$e]; 
		}
		
		return new Passport($res, $this->namespace);
	}
	
	public function optimistic() {
		$c = $this->result->filter();
		
		if ($c->rewind()) { return min($c->toArray()) > 0; }
		else { return true; }
	}
	
	public function pesimistic() {
		$c = $this->result->filter();
		
		if ($c->rewind()) { return min($c->toArray()) > 0; }
		else { return false; }
	}
	
}
