import matplotlib.pyplot as plt

x = [0.1, 0.3, 0.5]
y = [0.401939394, 1.047886076, 1.77965]

x2 = [0.1, 0.3, 0.5]
y2 = [0.529596154, 1.127322222, 1.613166667]

x3 = [0.1, 0.3, 0.5]
y3 = [0.515888889, 1.108109, 1.627237113]

x4 = [0.1, 0.3, 0.5]
y4 = [0.547892473, 1.08223, 1.616911765]

plt.plot(x, y, 'k:^', label = 'graph size : 40')
plt.plot(x2, y2, 'k-^', label = 'graph size : 60')
plt.plot(x3, y3, 'k--^', label = 'graph size : 80')
plt.plot(x4, y4, 'k-.^', label = 'graph size : 100')

plt.ylim(-0.5,3.0)

plt.xlabel('Ratio od added dummy node to the total node')
plt.ylabel('Increase in mean number of searching nodes')

plt.title('Comparing number of searching nodes based on graph size (large)')

plt.legend()

plt.show()
