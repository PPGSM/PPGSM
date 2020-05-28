t=performance/randomlarge
type=testnodetype
info=testtypeinfo
for i in $(seq 1 30); do
	./homomorphic_graph $t/randomGraphLarge $t/$type $t/$info >> $t/heuristic_10node_$i
done
