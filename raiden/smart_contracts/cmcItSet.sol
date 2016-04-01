
/*
    This is a very much work in progress draft of the data structure, 
    mostly used for testing purposes so far.
*/


/// @dev Models a uint -> uint mapping where it is possible to iterate over all keys.
library IterableMapping
{
  struct itmap
  {
    mapping(address => IndexValue) data;
    KeyFlag[] keys;
    uint size;
  }
  struct IndexValue { uint keyIndex; string value; }
  struct KeyFlag { address key; bool deleted; }
  function insert(itmap storage self, address key, string value) returns (bool replaced)
  {
    uint keyIndex = self.data[key].keyIndex;
    self.data[key].value = value;
    if (keyIndex > 0)
      return true;
    else
    {
      keyIndex = self.keys.length++;
      self.data[key].keyIndex = keyIndex + 1;
      self.keys[keyIndex].key = key;
      self.size++;
      return false;
    }
  }
  function remove(itmap storage self, address key) returns (bool success)
  {
    uint keyIndex = self.data[key].keyIndex;
    if (keyIndex == 0)
      return false;
    delete self.data[key];
    self.keys[keyIndex - 1].deleted = true;
    self.size --;
  }
  function contains(itmap storage self, address key) returns (bool)
  {
    return self.data[key].keyIndex > 0;
  }
  function atIndex(itmap storage self, address key) returns (uint index)
  {
      return self.data[key].keyIndex;
  }
  function iterate_start(itmap storage self) returns (uint keyIndex)
  {
    return iterate_next(self, uint(-1));
  }
  function iterate_valid(itmap storage self, uint keyIndex) returns (bool)
  {
    return keyIndex < self.keys.length;
  }
  function iterate_next(itmap storage self, uint keyIndex) returns (uint r_keyIndex)
  {
    keyIndex++;
    while (keyIndex < self.keys.length && self.keys[keyIndex].deleted)
      keyIndex++;
    return keyIndex;
  }
  function iterate_get(itmap storage self, uint keyIndex) returns (address key, string value)
  {
    key = self.keys[keyIndex].key;
    value = self.data[key].value;
  }
}

// How to use it:
contract User
{
  // Just a struct holding our data.
  IterableMapping.itmap data;
  // Insert something
  function insert(address k, string v) returns (uint size)
  {
    // Actually calls itmap_impl.insert, auto-supplying the first parameter for us.
    IterableMapping.insert(data, k, v);
    // We can still access members of the struct - but we should take care not to mess with them.
    return data.size;
  }
  // Computes the sum of all stored data.
  /*
  function sum() returns (uint s)
  {
    for (var i = IterableMapping.iterate_start(data); IterableMapping.iterate_valid(data, i); i = IterableMapping.iterate_next(data, i))
    {
        var (key, value) = IterableMapping.iterate_get(data, i);
        s += value;
    }
  }*/

  function get(address k) returns (address key, string value) {
      uint index = IterableMapping.atIndex(data, k);
      IterableMapping.iterate_get(data, index);
  }
}
