### ecrecover

*     py took: 32.09secs / 32091μs per op / 31 recoveries per sec
*     cy took: 8.26secs / 8260μs per op  / 121 recoveries per sec
*     c  takes: 300μs per op / 3000 recoveries per sec

### ed25519 https://github.com/orlp/ed25519

*     Message signing (short message): 87us (11494 per second)
*     Message verifying (short message): 228us (4386 per second)

### ed25519 donna

*     https://github.com/floodyberry/ed25519-donna
*     100K cycles per sign / 400k cycles per verify
*     @ 1GHz: 10.000 signs / 2.500 verifies

### ed25519 pycryptopp:

*    https://github.com/tahoe-lafs/pycryptopp
*    1679 signatures per second
*    523 verifies per second

### python-ed25519

*    1666 signatures
*    500 verifies


### sha3:
*     697k per second

### merkle tree:
*    60k additions per second

### merkleroot:
*    200K additions per second


### Pathfinding:
*     80k paths/s in a 1000 x 5 network
*     75k paths/s in a 1000 x 10 network
*     16k paths/s in a 10000 x 5 network

### De/serializations:
*     30k TXs per second

### udp messages per second:
*     http://nichol.as/asynchronous-servers-in-python
*     2x20k measured = 40k # 1024 bytes

```
Time per round:
on receive
    receive Msg:     15μs   #
    deserialize Msg  30μs   # 30 deserializations
    recover:        260μs   #
    serialize Ack:   30μs   # acks are not signed
    send Ack:        15μs
                    350μs
always:
    pathfinding:     20μs   # 50k paths / second
    businesslogic   250μs   # 2000 Locked Transfers / second (send + receive)
                    270μs
on respond
    signing Msg:    170μs
    serialize Msg:   30μs
    send Msg:        15μs
    receive Ack:     15μs
                    320μs
----------------------------------------
                    940μs
full:  940μs
half:  620μs


Mediated Transfer: 2f+2h Messages = 1.8 + 1.24 = 3ms
    C: TransferRequest
    A: MediatedTransfer
    B: MediatedTransfer
    C: HashLock
    B: HashLock

Exchange: 8f+2h Messages = 7.5 + 1.24 ms = 9ms
    A: ExchangeRequest
    B: ExchangeRequest
    C: ExchangeOffer -> A
    A: MediatedTransfer
    B: MediatedTransfer
    C: MediatedTransfer
    B: MediatedTransfer
    A: HashLock
    B: HashLock
    C: Ack


3ms per transfer:
300 cpu seconds per 100K transfers =  8 C4 instances

9ms per exchange:
900 cpu seconds per 100k exchanges = 25 C4 instances
450 cpu seconds per 100k transfers = 13 C4 instances

EC2:
C4 High-CPU Eight Extra Large (10 cpus, 2.6GHz base)
c4.8xlarge  60.0 GB     132 units   36 cores    0 GB (EBS only)
64-bit  10 Gigabit  $1.763 hourly

20 x C4: 720 cores
```

**Realworld results (no network yet):**

* transfers per second:164
* simulating 3 nodes, therefore:
* ~ 500 transfers per second and core
* 720 * 500 = 360.000 transfers per second



**Marginal Transaction Cost:**

* 3ms per transfer
* 300 transfers / second
* 1,080,000 transfers / hour
* .05 hourly 1 ec2 instance
* 1M transfer / 5ct
* 100M transfers / 

**Alternatively:**
Run the 50K TPS of Visa for a cost of $180 / day (on 150 ec2 instances)
