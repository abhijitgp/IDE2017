#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import pandas as pd
import os
import re
import csv
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import time

tic = time.clock()

print tic

def fix_Bytes(element):
    try:
        element = int(element)
    except ValueError:
        element = 0
    return element

def get_File(argv1):
    f= pd.read_csv(argv1,sep= " ",header=None, \
                     usecols = [0,3,4,5,6,7],\
                     names=['IP','T1','T2','Resource','Code','Bytes'], \
                     dtype={'IP': str,'T1': str,'T2':str,'Resource':object,'Code':object,'Bytes':str})
    f['T1']=f['T1'].str.strip('[]')
#    f['T2']=f['T2'].str.strip('[]')
    f['T1']=pd.to_datetime(f['T1'],format='%d/%b/%Y:%H:%M:%S')
    return f

def xtractResource(string):
    return string.split()[1]

def get_BusyTimes(series,maxm,times,frequency): 
      for i in range(maxm):
          one = series.rolling('H',min_periods=3600).sum().sort_values(ascending=False) # Sort the values in descending order 
          t_origin=one.index[0]-timedelta(seconds=3599)
          times.append(t_origin.strftime('%d/%b/%Y:%H:%M:%S -0400'))
          frequency.append(int(one.max()))
          begin = t_origin
          end = one.index[0]
          series = series [(series.index<begin) | (series.index>end)]
      return [times,frequency]


#################### Task 1 ###########################################
# List of most active hosts  (Top 10)
#######################################################################

def get_hosts(data,hosts,top):
    tophosts = Counter(data.IP).most_common(top)
    tophosts = map(lambda x: str(x).strip('()'),tophosts)
    with open(hosts,"w") as f:
        wr = csv.writer(f,delimiter="\n")
        wr.writerow(tophosts)

#################### Task 2 ###########################################
# List most acccessed resources that consumed most Bandwidth (Top 10)
#######################################################################
def get_resources(data,resources,top):
    data.Bytes=data.Bytes.apply(fix_Bytes)
    subdata = data[['Resource','Bytes']].groupby(['Resource'], as_index=True).agg(['sum'])
    rsrc = subdata.iloc[:,0].nlargest(top).reset_index()
    rsrc['split']=map(xtractResource,rsrc.Resource)
    rsrc = rsrc.iloc[:,[2]]
    with open(resources,"w") as f:
        rsrc.to_csv(f,sep=' ',header=None, index_label=None, index=False)

#################### Task 3 ###########################################
# List the Site's Busiest Periods (Top 10)
#######################################################################

def get_hours(data,hours,top):
    data = data.set_index(['T1'],drop=False)
    data_resampled = (data.T1.resample('S')
    .count()) #Resampling on "Seconds" scale to count # of occurances each second
    times=[]
    frequency=[]
    busy = get_BusyTimes(data_resampled,top,times,frequency)
    busy=pd.DataFrame(busy).transpose()
    with open(hours,'w') as m:
        busy.to_csv(m,sep=',',header=None, index_label=None, index=False)

#################### Task 4 ###########################################
# List Activities from likely malicious hosts
#######################################################################

def get_blocked(data,blocked):
    data = data.set_index(['T1'],drop=False)
    error_code = '401'
    dsub = data[data.Code==error_code]
    iptable = pd.DataFrame([],columns=['IP','Time'])
    for i in range(len(dsub)):
        ip = dsub.IP[i]
        t1 = dsub.index[i]
        t2 = t1 + timedelta(seconds=20)
        try:
            m = t2<iptable.Time[iptable.index[iptable.IP==ip][-1]]+timedelta(minutes=5)
        except IndexError:
            m = True #pd.Series([]) 
        if ((ip in iptable.IP.values) & m):
            pass # Already processed and within 5 min window
        else:
            d5=dsub.loc[(dsub.index>=t1)&(dsub.index<=t2)&(dsub.IP==ip)]
            if not (len(d5.loc[d5.IP==ip])<3):
                t3 = d5.index[2] # 3rd offense in 20 sec period
                breacher = data[(data.index>t3)&(data.index<=(t3+timedelta(minutes=5)))]
                breacher = breacher.query('IP==@ip')
                tlist=[ip,t3]
                iptable.loc[len(iptable)]=tlist
                with open(blocked,'a') as b:
                     breacher.to_csv(b,sep=' ',header=None, index_label=None, index=False)
            else:
                pass # because less than 3 attempts within 20 sec window 

#################### MAIN  ###########################################
os.chdir('C:/Musclebreath/fansite-analytics-challenge-master')

inf = './log_input/log.txt'
inf = 'C:/Users/gurjarpadhyea/Downloads/log.txt'

hosts = './log_output/hosts.txt'
resources = './log_output/resources.txt'
hours = './log_output/hours.txt'
blocked = './log_output/blocked.txt'

top=10
# Read data
data = get_File(inf) 

# Perform Tasks

#Task 1
get_hosts(data,hosts,top)
#Task2
get_resources(data,resources,top)
#Task3
get_hours(data,hours,top)
#Task4
get_blocked(data,blocked)

toc = time.clock()
total_time= toc - tic
total_time