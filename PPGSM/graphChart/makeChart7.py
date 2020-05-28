import matplotlib.pyplot as plt

x = [0.1, 0.2, 0.3, 0.4, 0.5]
y = [0.2468, 0.28668, 0.469, 0.70344, 0.78914]

x2 = [0.1, 0.2, 0.3, 0.4, 0.5]
y2 = [0.33784, 0.42272, 0.66962, 0.9981, 1.19538]

x3 = [0.1, 0.2, 0.3, 0.4, 0.5]
y3 = [-0.04938, 0.01058, -0.00024, 0.00416, -0.01622]

x4 = [0.1, 0.2, 0.3, 0.4, 0.5]
y4 = [0.30114, 0.31546, 0.53706, 0.65478, 0.97912]

x5 = [0.1, 0.2, 0.3, 0.4, 0.5]
y5 = [0.3945, 0.38558, 0.72894, 0.94966, 1.24118]

x6 = [0.1, 0.2, 0.3, 0.4, 0.5]
y6 = [0.06034, 0.04884, 0.02826, -0.0537, 0.01258]

plt.plot(x,y,'k--^',label = 'Barabasi-BC1')
plt.plot(x2, y2,'k--x', label = 'Barabasi-BC2')
plt.plot(x3, y3, 'k--D', label = 'Barabasi-RD')
plt.plot(x4, y4, 'k-^', label = 'Powerlaw-BC1')
plt.plot(x5, y5, 'k-x', label = 'Powerlaw-BC2')
plt.plot(x6, y6, 'k-D', label = 'Powerlaw-RD')

plt.ylim(-0.5,3.0)

plt.xlabel('Ratio of added dummy node to the total node')
plt.ylabel('Increase in mean number of searching nodes')

plt.title('Comparing heuristics based on different centrality with Barabasi & Power law graph')

plt.legend()

plt.show()
