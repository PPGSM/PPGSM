import matplotlib.pyplot as plt

x = [10, 12, 14, 16, 18]
y = [2.259054054, 2.198441558, 2.285, 2.267948718, 2.446721311]

x2 = [10, 12, 14, 16, 18]
y2 = [1.584375, 1.353658537, 1.691823529, 1.714388889, 1.586075949]

x3 = [10, 12, 14, 16, 18]
y3 = [1.401074, 1.389047363, 1.359352556, 1.528226129, 1.540484419]

x4 = [10, 12, 14, 16, 18]
y4 = [1.338206522, 1.28978956, 1.305189545, 1.325222556, 1.342102159]

x5 = [10, 12, 14, 16, 18]
y5 = [1.122786598, 1.181663125, 1.048288539, 1.165956, 1.388174186]

plt.plot(x, y, 'k:^', label = 'source node : 10%')
plt.plot(x2, y2, 'k-^',  label = 'source noed : 20%')
plt.plot(x3, y3, 'k--^', dashes = [2,2], label = 'source node : 30%')
plt.plot(x4, y4, 'k--^', dashes = [6,2], label = 'source node : 40%')
plt.plot(x5, y5, 'k-.', label = 'source node : 50%')

plt.ylim(-0.5,3.0)

plt.xlabel('Size of graph (total number of nodes)')
plt.ylabel('Increase in mean number of searching nodes')

plt.title('Comparing number of seaching nodes based on size of source node set')

plt.legend()

plt.show()
