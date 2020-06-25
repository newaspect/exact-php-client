<?php

namespace Picqer\Financials\Exact\Persistance;

use Picqer\Financials\Exact\Connection;

trait Storable
{
    /**
     * @return bool
     */
    abstract public function exists();

    /**
     * @param array $attributes
     */
    abstract public function fill(array $attributes);

    /**
     * @param int  $options
     * @param bool $withDeferred
     *
     * @return string
     */
    abstract public function json($options = 0, $withDeferred = false);

    /**
     * @return Connection
     */
    abstract public function connection();

    /**
     * @return string
     */
    abstract public function url();

    /**
     * @return mixed
     */
    abstract public function primaryKeyContent();

    /**
     * @return $this
     */
    public function save()
    {
        if ($this->exists()) {
            $this->fill($this->update());
        } else {
            $this->fill($this->insert());
        }

        return $this;
    }

    public function batchSave($callbacks = null, $metaData = null)
    {
        //TODO: normaal doen we hier een fill om de ID(primary key) in het object te zetten (daarna gaat hij over in de save)
        if ($this->exists()) {
            $this->batchUpdate($callbacks, $metaData);
        } else {
            $this->batchInsert($callbacks, $metaData);
        }

        return $this;
    }

    public function insert()
    {
        return $this->connection()->post($this->url(), $this->json(0, true));
    }

    public function update()
    {
        $primaryKey = $this->primaryKeyContent();

        return $this->connection()->put($this->url() . "(guid'$primaryKey')", $this->json());
    }

    public function delete()
    {
        $primaryKey = $this->primaryKeyContent();

        return $this->connection()->delete($this->url() . "(guid'$primaryKey')");
    }
    
    public function batchInsert($callbacks = null, $metaData = null)
    {
        return $this->connection()->batchPost($this->url(), $this->json(0, true), $callbacks, $this, $metaData);
    }

    public function batchUpdate($callbacks = null, $metaData = null)
    {
        $primaryKey = $this->primaryKeyContent();

        return $this->connection()->batchPut($this->url() . "(guid'$primaryKey')", $this->json(), $callbacks, $this, $metaData);
    }

    public function batchDelete($callbacks = null, $metaData = null)
    {
        $primaryKey = $this->primaryKeyContent();

        return $this->connection()->batchDelete($this->url() . "(guid'$primaryKey')", $callbacks, $this, $metaData);
    }
}
