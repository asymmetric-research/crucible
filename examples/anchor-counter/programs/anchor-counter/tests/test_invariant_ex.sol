// test/CounterInvariant.t.sol
import "forge-std/Test.sol";

contract Counter {
    uint256 public count;
    function increment() external { count++; }
    function decrement() external { if (count > 0) count--; }
}

contract CounterTest is Test {
    Counter counter;
    
    function setUp() public {
        counter = new Counter();
    }
   
    // Unit test - runs once 
    function test_increment() public {
        counter.increment();
        assertEq(counter.count(), 1);
    }

    // Stateless fuzz test - runs X times 
    function testFuzz_increment(uint8 times) public {
        times = uint8(bound(times, 1, 50));
        for (uint i = 0; i < times; i++) {
            counter.increment();
        }
        assertEq(counter.count(), times);
    }
}

// Stateful Fuzz test/invariant test
contract CounterInvariantTest is Test {
    Counter public counter;
    CounterHandler public handler;
    
    function setUp() public {
        counter = new Counter();
        handler = new CounterHandler(counter);
        
        // ⚠️ REQUIRED: Tell Foundry to only call handler functions
        targetContract(address(handler));
    }
    
    // ===== INVARIANT =====
    function invariant_countNeverNegative() public view {
        assertGe(counter.count(), 0);
    }
}

// Handler contains the actions
contract CounterHandler {
    Counter public counter;
    
    constructor(Counter _counter) {
        counter = _counter;
    }
    
    // ===== ACTIONS =====
    function increment() public {
        counter.increment();
    }
    
    function decrement() public {
        counter.decrement();
    }
}
