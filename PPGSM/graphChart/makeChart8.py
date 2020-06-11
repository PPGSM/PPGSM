import matplotlib.pyplot as plt

x = [0.1, 0.2, 0.3, 0.4, 0.5]
y = [0.044101, 0.089628, 0.137645, 0.1785, 0.227310811]

x2 = [0.1, 0.2, 0.3, 0.4, 0.5]
y2 = [0.03860360, 0.076784188, 0.113824786, 0.143087607, 0.183225108]

x3 = [0.1, 0.2, 0.3, 0.4, 0.5]
y3 = [0.033416988, 0.063402778, 0.095274725, 0.132561225, 0.161919643]

x4 = [0.1, 0.2, 0.3, 0.4, 0.5]
y4 = [0.026334459, 0.056768092, 0.088309295, 0.113518836, 0.140400641]

x5 = [0.1, 0.2, 0.3, 0.4, 0.5]
y5 = [0.02462963, 0.05365812, 0.078985507, 0.101783154, 0.134899818]


plt.plot(x, y, 'k:^', label = 'graph size : 10')
plt.plot(x2, y2, 'k-^', label = 'graph size : 12')
plt.plot(x3, y3, 'k--^', dashes = [2,2,4,4], label = 'graph size : 14')
plt.plot(x4, y4, 'k--^', dashes = [4,3], label = 'graph size : 16')
plt.plot(x5, y5, 'k-.^', label = 'graph size : 18')

plt.ylim(0.0,0.25)

plt.xlabel('Ratio od added dummy node to the total node')
plt.ylabel('Increase in mean number of searching nodes divided by graph size')

plt.title('Variation according to the ratio of added dummy nodes on random graph')

plt.legend()

plt.show()
