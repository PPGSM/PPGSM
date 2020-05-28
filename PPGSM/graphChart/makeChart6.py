import matplotlib.pyplot as plt

x = [0.1, 0.2, 0.3, 0.4, 0.5]
y = [0.417727, 0.902742, 1.506286, 1.907077, 2.402615]

x2 = [0.1, 0.2, 0.3, 0.4, 0.5]
y2 = [0.443333, 0.965846, 1.421739, 1.832097, 2.428197]

x3 = [0.1, 0.2, 0.3, 0.4, 0.5]
y3 = [0.480159, 0.817538, 1.011884, 1.188033, 1.244032]

x4 = [0.1, 0.2, 0.3, 0.4, 0.5]
y4 = [-0.01, -0.032, 0.020725, 0.017419, -0.01852]

plt.plot(x, y, label = 'PC', color = 'k', marker = 'o')
plt.plot(x2, y2, label = 'BC1', color = 'k', marker = '^')
plt.plot(x3, y3, label = 'BC2', color = 'k', marker = 'x')
plt.plot(x4, y4, label = 'RD', color = 'k', marker = 'D')

plt.ylim(-0.5,3.0)

plt.xlabel('Ratio of added dummy node to the total node')
plt.ylabel('Increase in mean number of searching nodes')

plt.title('Comparing heuristics based on different centrality with rando graph')

plt.legend()

plt.show()
