import numpy as np # array manipulation
import pandas as pd # data manipulation
import matplotlib.pyplot as plt # plotting
import seaborn as sns # plotting
import dc_stat_think as dcst
my_digtool = [163.78,191.10,207.36,427.44,530.15,162.23,515.54,237.52,1044.40,171.778,1718.16,303.36,125.72,582.50,419.07,281.77,163.09,149.34,176.13,152.73,462.29,881.23,170.54,180.31]
localserver = [2,1.7,3.1,2,2.1,2.2,1.9,1.7,10.7,4.4,51.4,3.9,3.3,30.3,32.0,3.3,4.4,3.2,5.3,2.9,2.5,3.0,3.4,3.2]
Googlecloud = [19.6,17.5,61.2,7.5,88.6,15.8,279.7,114.6,155.8,8.2,141.3,9.5,26.1,118.6,128.7,14.3,8.1,7.1,22.7,9.5,82.7,9.0,6.9,14.7]
a,b = dcst.ecdf(my_digtool)
c, d = dcst.ecdf(localserver)
e, f = dcst.ecdf(Googlecloud)
_ = plt.plot(a, b*100, linestyle='--', lw = 2)
_ = plt.plot(c,d*100, linestyle='-',lw=2)
_ = plt.plot(e,f*100, linestyle='-.',lw=2)
_ = plt.legend(("my_digtool", "localserver","Google"))

_ = plt.xlabel('Resolution Time (MS)', size = 14)
_ = plt.ylabel('Percentage', size = 14)
plt.show()