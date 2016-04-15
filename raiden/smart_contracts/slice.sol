contract Slicer {

    function slice(bytes a, uint start, uint end) returns (bytes n) {
        if (a.length < end) throw;
        if (start < 0) throw;
        if (start > end) throw;
        n = new bytes(end-start);
        for ( uint i = start; i < end; i ++) { //python style slice
            n[i-start] = a[i];
        }
    }
    
    function compareStrings(string _a, string _b) returns (int) {
        bytes memory a = bytes(_a);
        bytes memory b = bytes(_b);
        uint minLength = a.length;
        if (b.length < minLength) minLength = b.length;
        //@todo unroll the loop into increments of 32 and do full 32 byte comparisons
        for (uint i = 0; i < minLength; i ++)
            if (a[i] < b[i])
                return -1;
            else if (a[i] > b[i])
                return 1;
        if (a.length < b.length)
            return -1;
        else if (a.length > b.length)
            return 1;
        else
            return 0;
    }
    
    function compareBytes(bytes a, bytes b) returns (int) {
        uint minLength = a.length;
        if (b.length < minLength) minLength = b.length;
        //@todo unroll the loop into increments of 32 and do full 32 byte comparisons
        for (uint i = 0; i < minLength; i ++)
            if (a[i] < b[i])
                return -1;
            else if (a[i] > b[i])
                return 1;
        if (a.length < b.length)
            return -1;
        else if (a.length > b.length)
            return 1;
        else
            return 0;
    }
    
    function testConvert() returns (address y) {
        y = 0x123456;
        //bytes memory add = '0x123456';
        //address s = add;
        //y = t == s;
    }

    function testSlice() returns (bool yes, bool wow) {
        string memory res = string(slice("foobar", 0, 4));
        string memory t = "foob";
        bytes memory sli = slice("brainbot", 5, 8);
        bytes memory s = "bot";
        wow = compareBytes(sli, s) == 0;
        yes = compareStrings(t, res) == 0;
    }
}
