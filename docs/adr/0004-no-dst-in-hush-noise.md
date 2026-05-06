# No DST in hush-noise; reconsider for hush-sync

We evaluated Deterministic Simulation Testing (DST) as a testing strategy for `hush-noise`.

DST is the right tool for stateful distributed protocols with complex failure modes — consensus algorithms, CRDTs, multi-party sync with reordering and partitions. `hush-noise` is a point-to-point handshake library: its failure surface is a single TCP connection that may drop or deliver partial reads. That failure surface is fully exercisable with a standard TCP loopback test and a fault-injecting `io.Reader`/`io.Writer` wrapper. DST would add significant complexity for no proportional coverage gain here.

The decision deferred to `hush-sync`: the relay, conflict resolution (last-write-wins with vector timestamps), and multi-device partition scenarios are exactly the kind of stateful distributed problem DST was designed for. Revisit when `hush-sync` reaches that phase.
