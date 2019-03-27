# R80.X MDS Assesment

For R80.10 this script uses functions that were included in JHF70 or later.  See SK121292 for more details.

Script to gather stats on an R80 MDS Server including the following
  - Total memory used per CMA
  - Total number of objects
  - Total number of user created objects
  - Total number of rules
  - Total number of NAT rules
  - Total number of Policy Packages
  
Status output will be printed on the screen as the script is running and a CSV report is created for each CMA that is on the MDS.

Here is an example of the output.

CMA_NAME,Total_Memory,Total_Objects,Custom_Objects,NumPolices,TotalRulesPerCMA,NumNATRulesPerCMA
CMA1,1,10755,1025,1,4,2
CMA2,3,9732,2,1,2,2
CMA3,3,9732,2,1,2,2
CMA4,3,8910,1,1,1,2
CMA5,3,8910,1,1,1,2
