if [[ -d $1 ]]; then

        for files in $1/*
        do
                f="$(basename -- $files)"
                if [ 'testnodetype' = "$f" ]; then
                        :
                elif [ 'testtypeinfo' = "$f" ]; then
                        :
                elif [ 'a.out' = "$f" ]; then
                        :
                elif [ 'createRandomGraph.cpp' = "$f" ]; then
                        :
		elif [ 'makeRandomGraph.py' = "$f" ]; then
                        :
                else
                        ./homomorphic_graph $files $1/testnodetype $1/testtypeinfo;
                fi;
        done
fi
