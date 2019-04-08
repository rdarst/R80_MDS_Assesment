#!/bin/bash

JQ=${CPDIR}/jq/jq

#
# Setup Function to call the commands and parse all the results of the command
# Note this only works for objects and not access rules/layers  !!!!
#

mgmt_cli_query () {

 JQ=${CPDIR}/jq/jq
 FINISHED=false
 ITERATIONS=0
 LIMIT="0"
 OFFSET="0"
 OBJECTS=""

 while [ $FINISHED == false ]
	do

	  OFFSET=$[$LIMIT*$ITERATIONS]
	  OUTPUT=$(mgmt_cli "$@" offset $OFFSET)

	  if [ $? -ne 0 ]; then
			echo $OUTPUT
			exit 1
	  fi

	  TOTAL=$(echo ${OUTPUT} | ${JQ} .total )
	  FROM=$(echo ${OUTPUT} | ${JQ} .from )
	  RECEIVED_OBJ=$(echo ${OUTPUT} | ${JQ} .to )
	  OBJECTS+=$(echo ${OUTPUT} | ${JQ} .objects[])
	  OBJECTS+=$'\n'

	  if (($TOTAL == $RECEIVED_OBJ)); then
		FINISHED=true
	  fi

	  if [ "$LIMIT" -eq "0" ]; then
		LIMIT=$RECEIVED_OBJ
	  fi
	  let ITERATIONS=$ITERATIONS+1
 done

 echo "${OBJECTS}" | ${JQ} -s .

}

#####################################################################
###  Start Gathering data
#####################################################################

#Set timestamp
TIMESTAMP=$(date +"%s")
echo "CMA Details will be output to CMA_DETAIL_$TIMESTAMP.csv"
echo "CMA_NAME,Total_Memory,Total_Objects,Custom_Objects,NumPolices,TotalRulesPerCMA,NumNATRulesPerCMA" > CMA_DETAIL_$TIMESTAMP.csv

#Login at the MDS level and get the CMA list
echo "Logging in Read-Only to the MDS level to retreive CMA list"
MDSSID=$(mgmt_cli -r true login read-only true --format json |jq -r '.sid')
CMALIST=$(mgmt_cli show-domains limit 250 --session-id ${MDSSID} --format json | jq -r '.objects[] | [.name, .uid] |@csv')
echo "Logging out of Read-Only session to R80 MDS"
mgmt_cli logout --session-id $MDSSID --format json | ${JQ} -r '.message'

CMA_COUNT=$(echo "$CMALIST" | wc -l)
echo "Total CMA Count is $CMA_COUNT"

#Start Loop for each CMA
while read -r cma; do

#Gather CMANAME and CMA UID
CMANAME=$(echo $cma | cut -d ',' -f 1 | tr -d '"')
CMAUID=$(echo $cma | cut -d ',' -f 2 | tr -d '"')

#Login using read only to R80.X
echo "Logging into CMA ==> $CMANAME with UID $CMAUID"
SID=$(mgmt_cli -r true login read-only true domain $CMAUID --format json |jq -r '.sid')

# Get the Object data
RESULT=$(mgmt_cli_query show objects limit 200 details-level full show-membership false dereference-group-members false --format json --session-id $SID)
DETAIL=$(echo "${RESULT}" | ${JQ} -r -s 'map(.[].type)| reduce .[] as $i ({}; setpath([$i]; getpath([$i]) + 1))| to_entries |.[] | [.key, .value] |@csv')
CUSTOM=$(echo "${RESULT}" | ${JQ} -r '.[]| [."meta-info".creator, .type] |@csv ' |grep -v System |wc -l )
DEFAULT=$(echo "${RESULT}" | ${JQ} -r '.[]| [."meta-info".creator, .type] |@csv ' |grep System |wc -l )
TOTAL=$((  CUSTOM + DEFAULT ))

#echo "DETAILS ${DETAIL}"
echo "User Created Objects = ${CUSTOM}"
echo "System Created Objects = ${DEFAULT}"
echo "TOTAL Objects = ${TOTAL}"

# Get the number of policy packages
PACKAGES=$(mgmt_cli show-packages limit 500 --format json --session-id $SID)
PACKAGESNUM=$(echo "${PACKAGES}" | ${JQ} -r '.total'  )
PACKAGENAME=$(echo "${PACKAGES}" | ${JQ} -r '.packages[].name')

NATRULETOTAL=0
echo "Total number of Policy Packages = ${PACKAGESNUM}"
while read -r line; do
    PACKAGE=$(mgmt_cli show package name "$line" --format json --session-id $SID)
    ACCESSLAYER=$(echo "${PACKAGE}" | ${JQ} -r 'select(."access-layers" != null) | ."access-layers"[].uid')
    ACCESSLAYERNUM=$(echo "${PACKAGE}" | ${JQ} -r 'select(."access-layers" != null) |."access-layers"[].uid' | wc -l)
    THREATLAYER=$(echo "${PACKAGE}" | ${JQ} -r 'select(."threat-layers" != null) |."threat-layers"[].uid')
    THREATLAYERNUM=$(echo "${PACKAGE}" | ${JQ} -r 'select(."threat-layers" != null) |."threat-layers"[].uid' |wc -l)
    NATRULEBASE=$(mgmt_cli show nat-rulebase package "$line" show-membership false dereference-group-members false limit 1 --format json --session-id $SID | ${JQ} -r '.total')
    NATRULETOTAL=$((NATRULETOTAL + NATRULEBASE))
    TOTALRULES=0
    while read -r layer; do
      LAYERRULENUM=$(mgmt_cli show-access-rulebase uid $layer details-level uid show-membership false dereference-group-members false limit 1 --format json --session-id $SID |${JQ} '.total')  
      TOTALRULES=$(( TOTALRULES + LAYERRULENUM )) 
    done <<< "${ACCESSLAYER}"
    echo "Policy Package $line AccessLayers=${ACCESSLAYERNUM} ThreatLayers=${THREATLAYERNUM} TotalRules=${TOTALRULES} NatRules=${NATRULEBASE}"
done <<< "${PACKAGENAME}"

# Get the number of access-layers 
LAYERS=$(mgmt_cli show-access-layers limit 500 --format json --session-id $SID)
LAYERNUM=$(echo "${LAYERS}" | ${JQ} -r '.total'  )
LAYERUID=$(echo "${LAYERS}" | ${JQ} -r '."access-layers"[].uid')

TOTALLAYERRULES=0
echo "Total number of access-layers = ${LAYERNUM}"
while read -r line; do
    ACCESSLAYER=$(mgmt_cli show access-rulebase uid "$line" details-level uid --format json --session-id $SID)
    ACCESSLAYERNAME=$(echo "${ACCESSLAYER}" | ${JQ} -r '.name')
    ACCESSLAYERRULENUM=$(echo "${ACCESSLAYER}" | ${JQ} -r '.total')
    echo "Access Layer ${ACCESSLAYERNAME} TotalRules=${ACCESSLAYERRULENUM} "
    TOTALLAYERRULES=$(( TOTALLAYERRULES + ACCESSLAYERRULENUM ))
done <<< "${LAYERUID}"

echo "Total Access Rules in all Access Layers ${TOTALLAYERRULES}"
echo "Total NAT Rules in all Policy Packages ${NATRULETOTAL}"
MEMORY=$(ps aux |grep $CMANAME | awk 'BEGIN { sum=0 } {sum=sum+$6; } END {printf("%.1s",sum / 1024)}')
echo "$CMANAME,${MEMORY},${TOTAL},${CUSTOM},${PACKAGESNUM},${TOTALLAYERRULES},${NATRULETOTAL}" >> CMA_DETAIL_$TIMESTAMP.csv
# Do the right thing and logout after we are done and clear the session :)
echo ""
echo "Logging out of Read-Only session to R80 CMA $CMANAME"
mgmt_cli logout --session-id $SID --format json | ${JQ} -r '.message'

done <<< "$CMALIST"
