basic()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 basic
}

client_gsm()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 client_gsm
}

cloud_gsm()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 cloud_gsm
}

ind_poas()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 ind_poas
}

rosi()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 rosi
}

risk()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 risk
}

cum_poas()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 cum_poas
}

spl()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 spl
}

mpl()
{
	./homomorphic_graph sampleData/graphinfo1 sampleData/graphinfo2 sampleData/graphinfo3 mpl
}

if test $# -eq 0 ; then
  basic
else
  "$@"
fi
