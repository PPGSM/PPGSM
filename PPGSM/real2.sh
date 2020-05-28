t=performance/real2
type=testnodetype
info=testtypeinfo
for i in $(seq 1 30); do
	./homomorphic_graph $t/realGraph2 $t/$type $t/$info >> $t/heuristic_10node_$i
done
