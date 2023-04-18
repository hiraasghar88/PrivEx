#!/usr/bin/python3

import TACQ
from TACQ import TACQ
import argparse
import constraint
from constraint import Problem
from datetime import datetime, date, time, timedelta
# os.system("color")
import math
from sympy.solvers.diophantine import *
from sympy import *
import re
import os
import sys

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)


"""
Comptatibility checking between Privacy and Utility policies

usage: CompatibiltyChecking.py [-h|--help] [-v|--verbose [<levels>]] [-p|--privacy <file>] [-u|--utility <file>]

arguments:
  -h | --help    : Show this help and exit
  -v | --verbose : Specify levels of details
                    1 -> query rewritting
                    2 -> union of UQs
                    3 -> testing graph inclusion
                    4 -> testing filter conjunction satisfiability
                    5 -> testing graph homomorphism
                    6 -> testing isomorphism with same aggregate and same time windows
                    7 -> testing incompatibility with same aggregate and different time windows
  -p | --privacy : file containing the privacy query, default value is 'privacy.sparql'
  -u | --utility : file containing the utility queries, default value is 'utility.sparql'
"""


def readTACQs(file, prefix):
    """
    Extracts queries from a file.

    inputs: - file name
            - prefix for query names
    output: - dictionary of numbered TACQs
    """
    if not isinstance(file, str):
        raise TypeError('The "file" parameter of readQueries() must be a string !')
    if not isinstance(prefix, str):
        raise TypeError('The "prefix" parameter of reqdQueries() must be a string !')

    queries = []
    TACQs = {}
    l=""
    ll=[]
    qqNum=1
    
    with open(resource_path('UQs.txt'),"r") as ufile:
                
        for i,j in enumerate(ufile):
            if i>0 and j.startswith("UQ"):
                        l= str(l)+(j[0:])
                        ll=re.findall(r'\d+', str(l))         
                        ll.append('8')
                        #print(ll)
                        #print(type(ll))
                        
            
    qNum = ll[0]
    #print(ll[0])
    #ll=[]
    
    # read the file
    inputFile = open(file)
    lines = inputFile.readlines()
    # convert it into a string (easier to split)
    content = ''
    for l in lines:
        content = content + ' ' + l
    # check that there is a SELECT in the file
    first = content.find('SELECT')
    if first == -1:
        raise Exception('No SELECT in the file !')
    rest = content[first:]
    queries = rest.split('SELECT')
    # remove empty queries
    while '' in queries:
        queries.remove('')
    # convert queries into TACQs
    
    if prefix.startswith("PQ"):
        for q in queries:
            q = 'SELECT' + str(q)
            tacq = TACQ()
            tacq.parse(q) 
            TACQs[prefix + str(qqNum)] = tacq                   
            qqNum=qqNum+1
        return TACQs
      
    if prefix.startswith("UQ"):
        for p, q in enumerate (queries):
            for i,j  in enumerate(ll):
                if p==i:
                    if len(ll)>2:
                        
                        q = 'SELECT' + str(q)
                        tacq = TACQ()
                        tacq.parse(q) 
                        TACQs[prefix + str(qNum)] = tacq 
                        qNum=ll[i+1]
                    else:
                        q = 'SELECT' + str(q)
                        tacq = TACQ()
                        tacq.parse(q) 
                        TACQs[prefix + str(qNum)] = tacq 
        return TACQs

def checkGraphPatternOverlap(PQ, unionUQs, iso=False):
    """
    Check inclusion of the graph pattern of GP into the one of unionUQs.

    Verbose level: 3

    inputs: - PQ  : a privacy TACQ
            - unionUQs : a utility TACQ
    output: - a dictionnary { compatible, reasons } where:
                - compatible is a boolean
                - reasons is a dictionary associating line numbers to a list plainations if cas of incompatibility
    """
    if not isinstance(PQ, TACQ):
        raise TypeError('The parapeter "PQ" must be a rewritten privacy TACQ !')
    if not isinstance(unionUQs, TACQ):
        raise TypeError('The parameter "UQs" must be the TACQ containing the union of Utility graph patterns !')

    # Freeze union of graph patterns
    freezing = unionUQs.freeze()
    

    #-----------------------#
    vprint(3,'   ------------------------------------------')
    vprint(3,'   Most general freezing of the union of UQs:')
    vprint(3,'   ------------------------------------------')
    vprint(3,freezing.serialize(format="turtle"))
    #-----------------------#

    if '3' in mainArgs.verbose:
        unionUQs.printConstants()
        print()
    
    # Execute PQ on the freezing
    query = 'PREFIX res:<http://example.org/>\n'
    query = query + 'SELECT ' + PQ.listGPVars(timestamps=False) + '\n'
    query = query + 'WHERE { '
    
    for p in PQ.gp:
        query = query + p['subject'] + ' '
        query = query + 'ns1' + p['predicate'] + ' '
        
        if p['object'][0] != '?':
            query = query + '"' + p['object'] + '" . '

        else:
            query = query + p['object'] + ' . '
    query = query[:-3] + ' }'
 
    
    
    #-----------------------#
    vprint(3,'   ------------------------------------------------------------------------------------')
    vprint(3,'   SparQL execution on the freezing of the plain conjunctive part of the privacy query:')
    vprint(3,'   ------------------------------------------------------------------------------------')
    vprint(3,'\033[1;37mQuery:\033[0m')
    vprint(3,query)
    vprint(3)
    #-----------------------#

    result = freezing.query(query)
    

    vars = PQ.listGPVars(timestamps=False).split()
    vprint(3,'\033[1;37mResults:\033[0m')
    if '3' in mainArgs.verbose:
        printQueryResults(result, vars)

    #code for extracting variables and overlapping UQs
    global PQAL
    global PQALL
    global UQs_GPL
    global ReasonsJoins
    ReasonsJoins = []
    UQs_GPL=[]
    list_S=[]
    global FUQ
    global UQL
    FUQ=''
    UQL=''
    global SUQL
    SUQL=''
    global UQLL
    UQLL=[]   #List used to extract output varables for each overlapping UQ
    for row in result:        
        LS= str(row)
        list_S=re.findall(r"['\"](.*?)['\"]", LS)       
    
    UQS=[]    
    UQSS=[]
    
    for x,y in enumerate(list_S):
        for key, value in unionUQs.constants.items():
            if y==value:
                UQS.append(key)
                
    for x,y in enumerate(UQS):
        for key, value in unionUQs.variables.items():
            if y==key:
                UQSS.append(value)
   
    UQSS=sorted(list(set(UQSS)))
    global UQSL
    #result variables for UQs 
    UQSL=''
    for x,y in enumerate(UQSS):
        if x==0 and x!=(len(UQSS)-1):
            UQSL += '' +y
        if x!=0 and x!=(len(UQSS)-1):
            UQSL += ', ' +y
        if x!=0 and x==(len(UQSS)-1):
            UQSL += ' and ' +y
        if x==0 and x==(len(UQSS)-1):
            UQSL += '' +y

           
    
    #code for extracting answer set from PQs
    APQ=[]
    for line in result:
        # suppose it is not compatible
        comp = False 
        for v in range(len(vars)):
            if vars[v][1] == 'o':
                APQ.append(line[v])
    global list_APQ
    list_APQ=[]    
    for m,n in enumerate(APQ):        
        LAPQ= str(n)
        list_APQ.append(LAPQ)
   
    PQS=[]    
    PQSS=[]
    for x,y in enumerate(list_APQ):
        for key, value in unionUQs.constants.items():
            if y==value:
                PQS.append(key)
               
    for x,y in enumerate(PQS):
        for key, value in unionUQs.variables.items():
            if y==key:
                PQSS.append(value)
               
    PQSS=sorted(list(set(PQSS)))
       
    
    GUQs = readTACQs(mainArgs.utility, 'UQ')
    
    
    UQFilterVal=[]
    UQFilterOpl=[]
    #code to extract output variable of each UQ   
        
    
    for q in GUQs.keys():
        if len(PQ.filter)==0 and len(GUQs[q].filter)!=0:
            for r in GUQs[q].filter:
                if (str(r['opr'])[0]!='?') and (type(r['opr'])!= datetime):
                    if (str(r['comp'])== '>'):
                        r['opr']=int(r['opr'])+1
                        UQFilterVal.append(r['opr'])
                        UQFilterOpl.append(r['opl']+'1')
                    elif (str(r['comp'])== '<'):
                        r['opr']=int(r['opr'])-1
                        UQFilterVal.append(r['opr'])
                        UQFilterOpl.append(r['opl']+'1')
                    else:
                        UQFilterVal.append(r['opr'])
                        UQFilterOpl.append(r['opl']+'1')
    fres = {}
    for key in UQFilterOpl:
        for value in UQFilterVal:
            fres[key] = value
            UQFilterVal.remove(value)
    #print(fres)              
               
    
    for q in GUQs.keys():
        UQs_GPL.append(GUQs[q].gp)
        
      
    UQs_GPLI=[]
        
    UQs_GPL=str(UQs_GPL).replace("'subject':","")
    UQs_GPL=str(UQs_GPL).replace("'object':","")
    UQs_GPL=str(UQs_GPL).replace("'predicate':","")        
    UQs_GPL=str(UQs_GPL).replace("'","")
    UQs_GPL=str(UQs_GPL).replace('"',"")  
    UQs_GPL=str(UQs_GPL).replace('{',"")
    UQs_GPL=str(UQs_GPL).replace('}',".")
    UQs_GPL=str(UQs_GPL).replace('[',"")
    UQs_GPL=str(UQs_GPL).replace(']',"")
    UQs_GPL=str(UQs_GPL).replace(',',"")
    UQs_GPL=str(UQs_GPL).replace("timestamp: any","")
   
    UQs_GPL= str(UQs_GPL).split()
   
    
    SO=''
    UQG=[]
    for i,j in enumerate(UQs_GPL):
    
        if j[0]=='?':
            SO=str(j)+'1'
           
            UQG.append(SO)
        else:
            UQG.append(j)
   
            
    if len(PQ.filter)==0:      
        for k,v in fres.items():
            for i,j in enumerate(UQG):
                if k==j:
                    UQG=str(UQG).replace(str(j),str(v))
                    
    currenttime=datetime.now()    
    ctu=currenttime.strftime('%m-%d-%Y %H:%M:%S')
    
    UQs_GPL=str(UQG)
    
    UQs_GPL=str(UQs_GPL).replace("'","")
    UQs_GPL=str(UQs_GPL).replace('"',"")
    UQs_GPL=str(UQs_GPL).replace(',',"")
    UQs_GPL=str(UQs_GPL).replace('[',"")
    UQs_GPL=str(UQs_GPL).replace(']',"")
    UQs_GPL=str(UQs_GPL).replace('?',"")
    UQs_GPL=str(UQs_GPL).replace("timestamp:",",")   
    UQs_GPL=str(UQs_GPL).replace("timestamp.",str(ctu))
    UQs_GPL=str(UQs_GPL).replace("numberOfPersons1","1")
    UQs_GPL=str(UQs_GPL).replace("consumption1","3")
    UQs_GPL=UQs_GPL[:-1]
    UQs_GPL = '{'+UQs_GPL+'}'
   
    global CUQL
    CUQL=''
    global CUQLL
    CUQLL=[]
    for x,y in enumerate(PQS):
            CUQLL.append(y[3:-2])
                    
    CUQLL=sorted(list(set(CUQLL)))
    

    for x,y in enumerate(CUQLL):
                if x==0 and x!=(len(CUQLL)-1):
                    CUQL += '' +y
                    
                if x!=0 and x!=(len(CUQLL)-1):
                    CUQL += ', ' +y
                    
                if x!=0 and x==(len(CUQLL)-1):
                    CUQL += ' and ' +y
                    
                if x==0 and x==(len(CUQLL)-1):
                    CUQL += '' +y                
    PL=''
    PLL=[]
    global outputVariables
    global SVars
    global OutputConj
    OutputConj=[]
    outputVariables=[]  
    outputVariables=PQSS
    
    for q in GUQs.keys():
        SVars=GUQs[q].select  
        for i in outputVariables:
            if (q in CUQLL) and (i in SVars):
                OutputConj.append(f"Remove '{i}' from the output {q}!")
                
    global listPreUQ
    listPreUQ=[]
    global listPre
    listPre=[]
    global preReplace
    preReplace=[]
    global Predict
    Predict={}
    global PreUQ
    PreUQ=[]
    global OutputGen
    OutputGen=[]    
                
    #list of properties that can be generalized
    Predict = {
                "issda:numberOfPersons": "issda:familySize",
                "issda:yearlyIncome": "issda:yearlyIncomeRange",
                "issda:buildingAge": "issda:buildingAgeRange",
                "issda:chiefIncomeEarnerEducation": "issda:chiefIncomeEarnerEducationLevel"
                 }

                 
    PQpredicates= str(PQ.gp).split()
    for i in (PQpredicates):
            if i.startswith("'issda"):
                i=str(i).replace("',","")
                i=str(i).replace("'","")
                listPre.append(i)    
   
    for i,j in enumerate (listPre):
        for key, value in Predict.items():
                if j==key:
                    preReplace.append(key)
                    preReplace.append(value)
    
    for q in GUQs.keys():
        listPreUQ=[]
        if (q in CUQLL):
            PreUQ = str(GUQs[q].gp).split()
            for b in (PreUQ):
                if b.startswith("'issda"):
                    b=str(b).replace("',","")
                    b=str(b).replace("'","")
                    listPreUQ.append(b)                
            for i in listPreUQ:
                if i in listPre:
                    for key, value in Predict.items():                                
                        if i==key:                           
                            OutputGen.append(f"Generalize the property '{key}' with the property '{value}' {q}!")
      
              
              
    
    for i,j in enumerate(PQSS):
        if j[0]=='?':
            PL=j+'1'
            PLL.append(PL)
           
    if len(PQ.filter)==0:       
        for k,v in fres.items():                      
            for i,j in enumerate(PLL):                            
                if k==j:
                    PLL=str(PLL).replace(str(j),str(v))
              
    PQSS=PLL
    PQAL=str(PQSS).replace('?',"")
    PQAL=str(PQAL).replace("'","")
    PQAL=str(PQAL).replace('[',"")
    PQAL=str(PQAL).replace(']',"")
    PQAL=str(PQAL).replace('numberOfPersons1',"1")
    PQAL=str(PQAL).replace('consumption1',"3") 
    PQAL='('+PQAL+')'    
    PQALL=PQAL

    #replacing the values in data graph
    global CAUQ
    CAUQ=[] 
    global ReasonsJoinsConj
    ReasonsJoinsConj=[]
    for q in GUQs.keys():

        
        for i in CUQLL:                
                CAUQQ=[]
                if q==i:
                    CAUQ = GUQs[q].select
                    for i,j in enumerate(CAUQ):                        
                        if j[0]=='?':
                            j=j+'1'
                            CAUQQ.append(j)

                    
                    for r in (GUQs[q].gp):
                        if (r['timestamp'][0])=='?':
                            CAUQ = str(CAUQQ) + str(r['timestamp'] + '}')
                            CAUQ= str(CAUQ).replace("]",", ")
                    if len(PQ.filter)==0:        
                        for k,v in fres.items():
                     
                            for i,j in enumerate(CAUQQ):
                           
                                if k==j:
                                    CAUQQ=str(CAUQQ).replace(str(j),str(v))
                               
                    CAUQ= str(CAUQQ).replace("?","")                    
                    CAUQ= str(CAUQ).replace("'","")
                    CAUQ= str(CAUQ).replace("[","(")
                    CAUQ= str(CAUQ).replace("]",")")
                    CAUQ=str(CAUQ).replace('numberOfPersons1',"1")
                    CAUQ=str(CAUQ).replace('consumption1',"3")
                    ReasonsJoinsConj.append(f"    {CAUQ} for {q}")                                    
        
                    
             
    #code for extracting joins from queries
    joins=[]
    JL=[]
    if PQ.joins:
        vprint(3,f"Checking {PQ.prefix} join conditions for each line of the result by equating output constants:")
        vprint(3,PQ.toString('j'))
        j=(str(PQ.joins).split(','))
        for i,j in enumerate (j):
            if i==0:
                j1=(j[3:-1])                
                joins.append(j1)                
            else:
                j2=(j[2:-3])                
                joins.append(j2)
        
                
        for i,j in enumerate(joins):
            for key, value in PQ.variables.items():
                if j==key:
                    JL.append(value)
                    global JJL
                    JJL=set(JL)
                    JJL= str(JJL)
                    JJL=JJL[2:-2]
                     
                 
    # Check Theorem 4.1 and 4.3
   
    compatible = True
    reasons = {}
    Reasons = []
    # for each line of the query result
    lineNb = 1                   
                                           
    FrozenL=''               
    for line in result:
        # suppose it is not compatible
        comp = False
        reason = {}
        # test output variables: if no full PQ result can be obtained => compatible
        if not(iso):
            for v in range(len(vars)):
                if vars[v][1] == 'o' and line[v][0] != 'o':
                    comp = True
    
        # test all join conditions
        if not(comp):
            res = []
            for (l,r) in PQ.joins:                
                #left var
                il = vars.index(l)
                vl = line[il]
                # right var
                ir = vars.index(r)
                vr = line[ir]
                #test join: different value and one is not an output value => compatible
                if (vl[0] != 'o' or vr[0] != 'o') and (vl != vr):
                    comp = True
                elif not(comp) and vl != vr:
                    if not lineNb in reason.keys(): 
                        reason[lineNb] = [(vl, vr)]
                        
                    elif not (vl, vr) in reason[lineNb]:
                        reason[lineNb].append((vl, vr))
            if not(comp):
                reasons.update(reason.copy())        

        if not PQ.joins:
            Reasons.append(f"The freezing returns results for {PQ.prefix}")
            vprint()
           
        for r in reasons.keys():
            cond = ''
            for (v1, v2) in reasons[r]:
                cond = cond + f"{v1} == {v2} and "
            Reasons.append(f"A freezing where {cond[:-5]} returns results for {PQ.prefix} in line {str(r)}")        
            FrozenL= v1 + ',' + v2
            FrozenL=str(FrozenL)
            FrozenL= FrozenL.split(',')
            #print(FrozenL)
         # conclusion
        if not comp:
            compatible = False        
        lineNb = lineNb + 1   
        
    #code for extracting variables for UQs
    FL=[]
    for i,j in enumerate(FrozenL):
        for key, value in unionUQs.constants.items():
            if j==value: 
                FL.append(key)
   
    global Updated_FL            
    Updated_FL=[]
    UQsL=[]
    global outputJoins
    outputJoins=[]
    for x,y in enumerate(FL):
        for key, value in unionUQs.variables.items():
            if y==key:
                UQsL.append(key)
                outputJoins=value
                Updated_FL.append(value+'1')
    
    Updated_FL= str(Updated_FL).replace("?","")
    Updated_FL= str(Updated_FL).replace("'","")
    Updated_FL= str(Updated_FL).replace("[","")
    Updated_FL= str(Updated_FL).replace("]","")
    Updated_FL= str(Updated_FL).replace(",","")
    Updated_FL= str(Updated_FL).replace("numberOfPersons1","1")
    Updated_FL= str(Updated_FL).replace("consumption1","3")
    Updated_FL= Updated_FL.split()
    
    global UQs_GPLJ 
    UQs_GPLJ=UQs_GPL
    
    for i,j in enumerate(Updated_FL):
        UQs_GPLJ= UQs_GPLJ.replace(str(j),'occupier1')    
    
    global PQASS
    PQASS=PQALL
    
    for i,j in enumerate(Updated_FL):        
        PQASS= PQASS.replace(str(j),'occupier1')
        
    for x,y in enumerate(UQsL):
        UQLL.append(y[3:-2])                    
    UQLL=sorted(list((UQLL)))
    
       
    for x,y in enumerate(UQLL):
        if x==0 and x!=(len(UQLL)-1):
            UQL += '' +y                    
        if x!=0 and x!=(len(UQLL)-1):
            UQL += ', ' +y                    
        if x!=0 and x==(len(UQLL)-1):
            UQL += ' and ' +y                    
        if x==0 and x==(len(UQLL)-1):
            UQL += '' +y

    for x,y in enumerate(UQLL):
        if x==0 and x!=(len(UQLL)-1):
            SUQL += '' +y                    
        if x!=0 and x!=(len(UQLL)-1):
            SUQL += ', ' +y                    
        if x!=0 and x==(len(UQLL)-1):
            SUQL += ' or ' +y                    
        if x==0 and x==(len(UQLL)-1):
            SUQL += '' +y
        
             
    AUQL=[]
    AUQ=[]
    
    for q in GUQs.keys():
        for i in UQLL:
            AUQQ=[]
            if q==i:                
                AUQ = GUQs[q].select
                for i,j in enumerate(AUQ):                        
                        if j[0]=='?':
                            j=j+'1'
                            AUQQ.append(j)
                for r in (GUQs[q].gp):
                    if (r['timestamp'][0])=='?':
                        CAUQ = str(CAUQ) + str(r['timestamp'] + '}')
                        CAUQ= str(CAUQ).replace("]",", ")
                if len(PQ.filter)==0:        
                    for k,v in fres.items():
                        for i,j in enumerate(AUQQ):                       
                            if k==j:
                                AUQQ=str(AUQQ).replace(str(j),str(v))
                            
                AUQ= str(AUQQ).replace("?","")
                AUQ= str(AUQ).replace("'","")
                AUQ= str(AUQ).replace("[","(")
                AUQ= str(AUQ).replace("]",")")
                AUQ= str(AUQ).replace("numberOfPersons1","1")
                AUQ= str(AUQ).replace("consumption","1")
                for i,j in enumerate(Updated_FL):        
                    AUQ= AUQ.replace(str(j),'occupier1')                
                ReasonsJoins.append(f"    {AUQ} for {q}")
                OutputConj.append(f"Remove '{outputJoins}' from the output {q}!") 
                  
                               
    UpdatedFL=sorted(list(set(Updated_FL)))
            
    for x,y in enumerate(UpdatedFL):
            if x==0 and x!=(len(UpdatedFL)-1):
                FUQ += '' +y
            if x!=0 and x!=(len(UpdatedFL)-1):
                FUQ += ', ' +y
            if x!=0 and x==(len(UpdatedFL)-1):
                FUQ += ' and ' +y
            if x==0 and x==(len(UpdatedFL)-1):
                FUQ += '' +y      
                             
    
    return {'compatible' : compatible, 'reasons' : Reasons, 'results' : result}   

filterExp = ""


def condition(v1=0,  v2=0,  v3=0,  v4=0,  v5=0,  v6=0,  v7=0,  v8=0,  v9=0,  v10=0, 
              v11=0, v12=0, v13=0, v14=0, v15=0, v16=0, v17=0, v18=0, v19=0, v20=0, 
              v21=0, v22=0, v23=0, v24=0, v25=0, v26=0, v27=0, v28=0, v29=0, v30=0, 
              v31=0, v32=0, v33=0, v34=0, v35=0, v36=0, v37=0, v38=0, v39=0, v40=0, 
              v41=0, v42=0, v43=0, v44=0, v45=0, v46=0, v47=0, v48=0, v49=0, v50=0, 
              v51=0, v52=0, v53=0, v54=0, v55=0, v56=0, v57=0, v58=0, v59=0, v60=0, 
              v61=0, v62=0, v63=0, v64=0, v65=0, v66=0, v67=0, v68=0, v69=0, v70=0, 
              v71=0, v72=0, v73=0, v74=0, v75=0, v76=0, v77=0, v78=0, v79=0, v80=0, 
              v81=0, v82=0, v83=0, v84=0, v85=0, v86=0, v87=0, v88=0, v89=0, v90=0, 
              v91=0, v92=0, v93=0, v94=0, v95=0, v96=0, v97=0, v98=0, v99=0, v100=0):
    """
    Condition function for testing satisfiability
    """
    global filterExp
    return eval(filterExp)
    

def checkFilterConjunctionSatisfiability(PQ, unionUQs, results):
    """
    Checks the satisfiability of the conjunction of filter conditions of PQ and unionUQs according to the result of PQ over the most general freezing of unionUQs.

    Verbose level: 4

    inputs: - PQ       -> a privacy query to check
            - unionUQs -> union of utility queries GP, Filters and Joins
            - results  -> result of PQ evaluated on the most general freezing of unionQUs
    output: -  a dictionnary { compatible, reasons } where:
                - compatible is a boolean
                - reasons is a list of result line numbers where filter satisfiability has been detected
                - mappings is a dictionnary { line, mapping }
                    - line -> line number in results
                    - mapping -> mappings of PQ variables to unionUQs variables
    """

    global filterExp
    reasons = []
    mappings = {}

    # freeze unionQUs
    unionUQs.freeze()

    # compute union of PQ and UQs (GPs, filters and joins)
    bigQ = PQ.union(unionUQs)

    #-----------------------#
    if '4' in mainArgs.verbose:
        print("   ---------------------------------------------")
        print("   Conjunction of filter conditions of PQ an UQs")
        print("   ---------------------------------------------")
        print(bigQ.toString('jf'))
        print()
    #-----------------------#

    compatible = True
    lnb = 0
    vars = PQ.listGPVars(timestamps=False).split()

    #-----------------------#
    vprint(4,'   ============================================================================================================================')
    vprint(4,'   Verifying the filter expression over each answer of privacy query over the most general freezing of union of utility queries')
    vprint(4,'   ============================================================================================================================')
    vprint(4)
    vprint(4,f"   {PQ.prefix} result:")
    if '4' in mainArgs.verbose:
        printQueryResults(results, vars)
    vprint(4)
    vprint(4,"   -------------------")
    vprint(4,"   Variable assignment")
    vprint(4,"   -------------------")
    if '4' in mainArgs.verbose:
        bigQ.printConstants()
    vprint(4)
    #-----------------------#


    #
    # for each line in the result, test filter satisfiability
    #

    for line in results:
        lnb = lnb + 1

        #-----------------------#
        if '9' in mainArgs.verbose:
            print("\033[36m   ---------------\033[0m")
            print(f"\033[36m   Result line {lnb}\033[0m")
            print("\033[36m   ---------------\033[0m")
            for r in range(len(line)):
                print(vars[r], "=", line[r])
            print()
        #-----------------------#

        filterExp = ""
        problem = Problem()

        # work on Q, a copy of bigQ
        global Q
        Q = bigQ.copy()
         
        # parse given result to build overlap

        ## build variable correspondance
        Q.variables = {}

        ### for each var in PQ GP
        for v in range(len(vars)):
            # get corresponding constant un result line
            cst = str(line[v])

            # find corresponding variable name in UQs
            for (i,j) in Q.constants.items():
                if j == cst:
                    # rename PQ variable in Q
                   Q.variables[vars[v]] = i
        
        #-----------------------#
        if '9' in mainArgs.verbose:
            print("   --------------------")
            print("   Renamed PQ variables")
            print("   --------------------")
            Q.printVariables()
            print()
        #-----------------------#

        ## rename variables in filter
        for f in range(len(Q.filter)):
            try:
                opl = Q.variables[str(Q.filter[f]['opl'])]
            except KeyError:
                opl = Q.filter[f]['opl']
            comp = Q.filter[f]['comp']
            try:
                opr = Q.variables[str(Q.filter[f]['opr'])]
            except KeyError:
                opr = Q.filter[f]['opr']
            Q.filter[f] = {'opl' : opl, 'comp' : comp, 'opr' : opr}
        
        ## rename variables in joins
        toDel = []
        for n in range(len(Q.joins)):
            (i,j) = Q.joins[n]
            try:
                i = Q.variables[i]
            except KeyError:
                pass
            try:
                j = Q.variables[j]
            except KeyError:
                pass
            if not (i,j) in Q.joins and i != j:
                Q.joins[n] = (i,j)
            else:
                toDel.append(n)
        for n in reversed(toDel):
            del Q.joins[n]

            
        #-----------------------#
        if '4' in mainArgs.verbose:
            print("\033[36m   -------------------------------\033[0m")
            print(f"\033[36m   Rewritten filter for line {lnb}\033[0m")
            print("\033[36m   -------------------------------\033[0m")
            print(Q.toString("fj")[:-2])
            print()
        #-----------------------#
        
        # set types for UQ variables
        Q.typeVars()

        #-----------------------#
        if '4' in mainArgs.verbose:
            print('   =================================================')
            print('   Using a CSP solver to check Filter satisfiability')
            print('   =================================================')
            print()
        #-----------------------#

        ## prepare variable domains generation
        intVars = []
        strVars = []
        floatVars = []
        dateVars = []
        unknownVars = []

        intConst = []
        strConst = []
        floatConst = []
        dateConst = []
    
        ## list variables and constants by type in filter
        for f in Q.filter:
            # opl is a variable
            if isinstance(f['opl'], str) and f['opl'][0] == '?':
                if str(Q.varTypes[f['opl']]) == "<class 'int'>":
                    intVars.append(f['opl'])
                if str(Q.varTypes[f['opl']]) == "<class 'str'>":
                    strVars.append(f['opl'])
                if str(Q.varTypes[f['opl']]) == "<class 'float'>":
                    floatVars.append(f['opl'])
                if str(Q.varTypes[f['opl']]) == "<class 'datetime.datetime'>" or str(Q.varTypes[f['opl']]) == "<class 'datetime'>":
                    dateVars.append(f['opl'])
                if str(Q.varTypes[f['opl']]) == 'unknown':
                    unknownVars.append(f['opl'])
            
            # opl is a constant
            else:
                if isinstance(f['opl'], int):
                    intConst.append(f['opl'])
                elif isinstance(f['opl'], str):
                    strConst.append(f['opl'])
                elif isinstance(f['opl'], float):
                    floatConst.append(f['opl'])
                elif isinstance(f['opl'], datetime):
                    dateConst.append(f['opl'])

            # opr is a variable
            if isinstance(f['opr'], str) and f['opr'][0] == '?':
                if str(Q.varTypes[f['opr']]) == "<class 'int'>":
                    intVars.append(f['opr'])
                if str(Q.varTypes[f['opr']]) == "<class 'str'>":
                    strVars.append(f['opr'])
                if str(Q.varTypes[f['opr']]) == "<class 'float'>":
                    floatVars.append(f['opr'])
                if str(Q.varTypes[f['opl']]) == "<class 'datetime.datetime'>" or str(Q.varTypes[f['opl']]) == "<class 'datetime'>":
                    dateVars.append(f['opr'])
                if str(Q.varTypes[f['opr']]) == 'unknown':
                    unknownVars.append(f['opr'])

            # opr is a constant
            else:
                if isinstance(f['opr'], int):
                    intConst.append(f['opr'])
                elif isinstance(f['opr'], str):
                    strConst.append(f['opr'])
                elif isinstance(f['opr'], float):
                    floatConst.append(f['opr'])
                elif isinstance(f['opr'], datetime):
                    dateConst.append(f['opr'])


        # list variables by type in joins
        for n in range(len(Q.joins)):
            (i, j) = Q.joins[n]
            # Left variable i
            if str(Q.varTypes[i]) == "<class 'int'>":
                intVars.append(i)
            elif str(Q.varTypes[i]) == "<class 'str'>":
                strVars.append(i)
            elif str(Q.varTypes[i]) == "<class 'float'>":
                floatVars.append(i)
            elif str(Q.varTypes[i]) == "<class 'datetime.datetime'>" or str(Q.varTypes[i]) == "<class 'datetime'>":
                dateVars.append(i)
            else:
                unknownVars.append(i)

            # right variable j
            if str(Q.varTypes[j]) == "<class 'int'>":
                intVars.append(j)
            elif str(Q.varTypes[j]) == "<class 'str'>":
                strVars.append(j)
            elif str(Q.varTypes[j]) == "<class 'float'>":
                floatVars.append(j)
            elif str(Q.varTypes[i]) == "<class 'datetime.datetime'>" or str(Q.varTypes[i]) == "<class 'datetime'>":
                dateVars.append(j)
            else:
                unknownVars.append(j)


        # elimiate duplicates in lists and sort them
        intVars = list(set(intVars))
        strVars = list(set(strVars))
        floatVars = list(set(floatVars))
        dateVars = list(set(dateVars))
        unknownVars = list(set(unknownVars))

        intConst = sorted(list(set(intConst)))
        strConst = sorted(list(set(strConst)))
        floatConst = sorted(list(set(floatConst)))
        dateConst = sorted(list(set(dateConst)))


        # generate domains for constants and variables 
        intDomain = []
        strDomain = []
        floatDomain = []
        dateDomain = []
        unknownDomain = []
        constants = {}

        end = 0
        begin = end

        ## integer
        pos = begin
        for i in intConst:
            constants[i] = pos + len(intVars)
            pos = pos + len(intVars) + 1
        if pos != begin:
            end = pos + len(intVars)
            intDomain = range(begin, end)
            begin = end + 1

        ## str
        pos = begin
        for i in strConst:
            constants[i] = pos + len(strVars)
            pos = pos + len(strVars) + 1
        if pos != begin:
            end = pos + len(strVars)
            strDomain = range(begin, end)
            begin = end + 1

        ## float
        pos = begin
        for i in floatConst:
            constants[i] = pos + len(floatVars)
            pos = pos + len(floatVars) + 1
        if pos != begin:
            end = pos + len(floatVars)
            floatDomain = range(begin, end)
            begin = end + 1

        ## date
        pos = begin
        for i in dateConst:
            constants[i] = pos + len(dateVars)
            pos = pos + len(dateVars) + 1
        if pos != begin:
            end = pos + len(dateVars)
            dateDomain = range(begin, end)
            begin = end + 1

        ## unknown variables
        pos = begin
        end = begin + 2*len(unknownVars) + 1
        unknownDomain = range(begin, end)

        #-----------------------#
        if '9' in mainArgs.verbose:
            print("------------------")
            print("Constants encoding")
            print("------------------")
            for (i,j) in constants.items():
                print(i, "->", j)
            print()

            print("---------------------")
            print("Variables and domains")
            print("---------------------")
            if intVars:
                print("int variables    :", intVars)
                print("    domain       :", intDomain)
            if strVars:
                print("str variables    :", strVars)
                print("    domain       :", strDomain)
            if floatVars:
                print("float variables  :", floatVars)
                print("      domain     :", floatDomain)
            if dateVars:
                print("date variables   :", dateVars)
                print("     domain      :", dateDomain)
            if unknownVars:
                print("unknown variables:", unknownVars)
                print("        domain   :", unknownDomain)
            print()
        #-----------------------#
       
        # generate filter expression
        for f in Q.filter:
            if f['comp'].strip() == '=':
                comp = '=='
            else:
                comp = f['comp']

            if str(f['opl'])[0] == '?':
                opl = f['opl']
            else:
                opl = constants[f['opl']]

            if str(f['opr'])[0] == '?':
                opr = f['opr']
            else:
                opr = constants[f['opr']]
            filterExp = filterExp + f"{str(opl)} {comp} {str(opr)} and "
        for (i,j) in Q.joins:
            if i != j:
                filterExp = filterExp + f"{i} == {j} and "
        filterExp = filterExp[:-5]

                
        FL=filterExp.split()        
        duplicatesFL = [x for n, x in enumerate(FL) if x in FL[:n]]           
        duplicates = re.findall(r"[\_](.*?)[\_]", str(duplicatesFL))
        global FLL
        FLL=''
        for x,y in enumerate(duplicates):
                if x==0 and x!=(len(duplicates)-1):
                    FLL += '' +y
                if x!=0 and x!=(len(duplicates)-1):
                    FLL += ', ' +y
                if x!=0 and x==(len(duplicates)-1):
                    FLL += ' and ' +y
                if x==0 and x==(len(duplicates)-1):
                    FLL += '' +y
              
        
        # rename variables in filter expression
        filterVariables = {}

        n = 1
        exp = filterExp.split()
        
        
        #-----------------------#
        vprint(9)
        vprint(9,"   ------------------------------")
        vprint(9,"   Expression to be tested by CSP")
        vprint(9,"   ------------------------------")
        #-----------------------#

        for pos in range(len(exp)):
            if exp[pos][0] == '?':
                var = ''
                for (i,j) in filterVariables.items():
                    if j == exp[pos]:
                        exp[pos] = i
                        var = i
                if var == '':
                    var = f"v{n}"
                    filterVariables[var] = str(exp[pos])
                    exp[pos] = var
                    n = n + 1

        
        # test filter
        ## int variables
        for v in intVars:
            var = v
            for (i,j) in Q.variables.items():
                if i == v:
                    var = j
            for (i,j) in filterVariables.items():
                if j == var:
                    try:
                        problem.addVariable(i, intDomain)
                        #-----------------------#
                        vprint(9,i, "int :", intDomain)
                        #-----------------------#
                    except ValueError:
                        pass

        ## str variables
        for v in strVars:
            var = v
            for (i,j) in Q.variables.items():
                if i == v:
                    var = j
            for (i,j) in filterVariables.items():
                if j == var:
                    try:
                        problem.addVariable(i, strDomain)
                        #-----------------------#
                        vprint(9,i, "str :", strDomain)
                        #-----------------------#
                    except ValueError:
                        pass

        ## float variables
        for v in floatVars:
            var = v
            for (i,j) in Q.variables.items():
                if i == v:
                    var = j
            for (i,j) in filterVariables.items():
                if j == var:
                    try:
                        problem.addVariable(i, floatDomain)
                        #-----------------------#
                        vprint(9,i, "float :", floatDomain)
                        #-----------------------#
                    except ValueError:
                        pass

        ## date variables
        for v in dateVars:
            var = v
            for (i,j) in Q.variables.items():
                if i == v:
                    var = j
            for (i,j) in filterVariables.items():
                if j == var:
                    try:
                        problem.addVariable(i, dateDomain)
                        #-----------------------#
                        vprint(9,i, "date :", dateDomain)
                        #-----------------------#
                    except ValueError:
                        pass

        ## unknown variables
        for v in unknownVars:
            var = v
            for (i,j) in Q.variables.items():
                if i == v:
                    var = j
            for (i,j) in filterVariables.items():
                if j == var:
                    try:
                        problem.addVariable(i, unknownDomain)
                        #-----------------------#
                        vprint(9,i, "unknown :", unknownDomain)
                        #-----------------------#
                    except ValueError:
                        pass

        filterExp = ''
        for i in exp:
            filterExp = filterExp + i + ' '

        #-----------------------#
        vprint(9)
        vprint(9,'      ', filterExp)
        vprint(9)
        #-----------------------#


        # Test satisfiability
        problem.addConstraint(condition, list(filterVariables.keys()))
        res = problem.getSolution()
        
            

        #-----------------------#
        vprint(4,"   -----------")
        vprint(4,"   Test result")
        vprint(4,"   -----------")
        vprint(9,'  ', res)
        vprint(4)
        #-----------------------#

        if res:
            compatible = False
            reasons.append(lnb)
            mappings.update({ lnb : Q.variables })
    #replacing values of filter in mapping         
    FilterL=[]
    FilterListt=[]
    for key, value in Q.variables.items():        
        for f in PQ.filter:                   
            if key==f['opl']:
                if (str(f['opr'])[0]!='?') and (type(f['opr'])!= datetime):
                    FilterL.append(value)
                    if (str(f['comp'])== '>'):
                        f['opr']=int(f['opr'])+1
                        FilterL.append(f['opr'])
                    elif (str(f['comp'])== '<'):
                        f['opr']=int(f['opr'])-1
                        FilterL.append(f['opr'])
                    else:
                        FilterL.append(f['opr'])
                if (str(f['opr'])[0]!='?') and (type(f['opr'])== datetime):
                     FilterL.append(value)
                     if (str(f['comp'])== '>'):                        
                        
                        f['opr']= f['opr'] + timedelta(minutes=10)                                                   
                        FilterL.append(f['opr'])
                     elif (str(f['comp'])== '<'):                        
                        f['opr']= f['opr'] - timedelta(minutes=10)                                                   
                        FilterL.append(f['opr'])
                     else:
                        FilterL.append(f['opr'])   
               
    res_dct={}                    
    def Convert(FilterL):
        res_dct = {FilterL[i]: FilterL[i + 1] for i in range(0, len(FilterL), 2)}
        return res_dct
    FilterList=Convert(FilterL)
    

    for key, value in unionUQs.variables.items():
         for m,n in FilterList.items():
             if m==key:
                 FilterListt.append(value[1:]+'1')
                 FilterListt.append(n)
                 
    res_dct2={}                    
    def Convert(FilterListt):
        res_dct2 = {FilterListt[i]: FilterListt[i + 1] for i in range(0, len(FilterListt), 2)}
        return res_dct2
    FilterListG=Convert(FilterListt)
    global UQs_GPLG
    global PQALF
    global PQASSF
    global ReasonsJoinsF
    ReasonsJoinsF=[]
    global ReasonsJoinsConjF
    ReasonsJoinsConjF=[]
    UQs_GPLG=UQs_GPLJ
    for key, value in FilterListG.items():
        UQs_GPLG= UQs_GPLG.replace(str(key),str(value))
        PQALF= PQAL.replace(str(key),str(value))
        PQASSF= PQASS.replace(str(key),str(value))        
        for r,s in enumerate(ReasonsJoins):
            replaceF=str(s).replace(str(key),str(value))            
            ReasonsJoinsF.append(replaceF)        
        for r,s in enumerate(ReasonsJoinsConj):
            replaceConjF=str(s).replace(str(key),str(value))
            ReasonsJoinsConjF.append(replaceConjF)
                
 

          
                 
    return {'compatible' : compatible, 'reasons' : reasons, 'mappings' : mappings}



def checkIsomorphism(PQ, UQ):
    """
    Check graph homomorphism between two queries.

    Verbose level: 5

    inputs: - PQ -> a TACQ
            - UQ -> another TACQ
    output: - a boolean
    """
    if not isinstance(PQ, TACQ):
        raise TypeError('The parameter "PQ" of checkHomomorphism() must be a TACQ !')
    if not isinstance(UQ, TACQ):
        raise TypeError('The parameter "UQ" of checkHomomorphism() must be a TACQ !')

    # PQ and UQ must have the same size of graph pattern
    PQnbVars = len(PQ.listGPVars().split())
    UQnbVars = len(UQ.listGPVars().split())
    if PQnbVars != UQnbVars:
        print("Bad variable number !")
        return False

    # check  inclusion of PQ and UQ
    pq = PQ.copy()
    pq.extractJoins()
    pq.reify()

    uq = UQ.copy()
    uq.reify()

    res = checkGraphPatternOverlap(pq, uq, iso=True)
    if res['compatible']:
        vprint(5, f"\033[1;33m   The graph pattern of {PQ.prefix} is not included into the one of {UQ.prefix}.\033[0m")
        vprint(5)
        return False
    vprint(5, f"\033[1;33m   The graph pattern of {PQ.prefix} IS INCLUDED into the one of {UQ.prefix} !\033[0m")
    vprint(5)
    
    # check inclusion of UQ and PQ
    uq = UQ.copy()
    uq.extractJoins()
    uq.reify()

    pq = PQ.copy()
    pq.reify()

    res = checkGraphPatternOverlap(uq, pq, iso=True)
    if res['compatible']:
        vprint(5, f"\033[1;33m   The graph pattern of {UQ.prefix} is not included into the one of {PQ.prefix}.\033[0m")
        vprint(5)
        return False
    vprint(5, f"\033[1;33m   The graph pattern of {UQ.prefix} IS INCLUDED into the one of {PQ.prefix} !\033[0m")
    vprint(5)

    # check conjunction of filters satisfiability
    if PQ.filter or UQ.filter:
        res = checkFilterConjunctionSatisfiability(PQ, UQ, res['results'])
        if res['compatible']:
            vprint(5,f"\033[1;33m   The conjunction of Filter of {PQ.prefix} and {UQ.prefix} is not satisfiable.\033[0m")
            vprint(5)
            return False
        vprint(5,f"\033[1;33m   The conjunction of Filter of {PQ.prefix} and {UQ.prefix} IS SATISFIABLE !\033[0m")
        vprint(5)

    return True

def checkAggregateCompatibility1UQ(PQ, UQ):
    """
    Checks compatibility of one PQ and one UQ computing the same aggregate.

    Verbose level: 6

    inputs: - PQ -> original privacy TACQ with prefix
            - UQ -> renamed and reified utility TACQ
    output: - a dictionary { compatible, reasons }
                - compatible: boolean
                - reason: a summary of the explaination if incompatible
                - toCheck: a boolean meaning that this UQ has to be tested with other UQs
    """
    if not isinstance(PQ, TACQ):
        raise TypeError('The parameter PQ must be a TACQ !')
    if not isinstance(UQ, TACQ):
        raise TypeError('The parameter UQ must be a TACQ !')

    compatible = True
    toCheck = False

    # PQ and UQ without time windows must be incompatible

    ## work on copies of PQ and UQ
    
    pq1 = PQ.copy()
           
    pq1.extractJoins()
    pq1.reify()
       
    
    uq1 = UQ.copy()
    uq1.reify()

    ## testing graph inclusion
    res = checkGraphPatternOverlap(pq1, uq1)

    if res['compatible']:
        #-----------------------#
        vprint(6, f"   The conjunctive parts of {PQ.prefix} and {UQ.prefix} are compatible.\033[0m")
        vprint(6)
        #-----------------------#
        return { 'compatible' : compatible, 'reason' : '', 'toCheck' : toCheck }

    ## testing filter condition satisfiability
    if not pq1.filter:
        v = list(pq1.variables.keys())[0]
        pq1.filter = [{'opl' : v, 'comp' : '=', 'opr' : v}]
        
    res = checkFilterConjunctionSatisfiability(pq1, uq1, res['results'])

    if res['compatible']:
        #-----------------------#
        vprint(6, f"   The conjunctive parts of {PQ.prefix} and {UQ.prefix} compatible.\033[0m")
        vprint(6)
        #-----------------------#
        return { 'compatible' : compatible, 'reason' : '', 'toCheck' : toCheck }

    #-----------------------#
    vprint(6, f"   The conjunctive parts of {PQ.prefix} and {UQ.prefix} are incompatible.\033[0m")
    vprint(6, f"   \033[33m{PQ.prefix} MAY BE INCOMPATIBLE with {UQ.prefix} !\033[0m")
    vprint(6)
    #-----------------------#


    # PQ and UQ must compute the same aggregate

    ## Same function
    if pq1.aggregate['function'] != uq1.aggregate['function']:
        #-----------------------#
        vprint(6, f"   But {PQ.prefix} and {UQ.prefix} compute different aggregate functions.\033[0m")
        vprint(6)
        #-----------------------#
        return { 'compatible' : compatible, 'reason' : '', 'toCheck' : toCheck }

    ## Same variable
    ok = True
    mappings = res['mappings']

    ### Test if aggregate variable of PQ can be mapped to aggregate variable of UQ
    for l in mappings.keys():
        if uq1.aggregate['variable'] == mappings[l][pq1.aggregate['variable']]:
            ok = False
    if ok:
        #-----------------------#
        vprint(6, f"   But {PQ.prefix} and {UQ.prefix} compute the same '{pq1.aggregate['function']}' aggregate  on different variables.\033[0m")
        vprint(6)
        #-----------------------#
        return { 'compatible' : compatible, 'reason' : '', 'toCheck' : toCheck }

    #-----------------------#
    vprint(6,f"   Furthermore, {PQ.prefix} and {UQ.prefix} compute the same '{pq1.aggregate['function']}' aggregate on the same variable.\033[0m")
    vprint(6, f"   \033[33m{PQ.prefix} still MAY BE INCOMPATIBLE with {UQ.prefix} !\033[0m")
    vprint(6)
    #-----------------------#


    # PQ and UQ graph patterns must be isomorphic
    pq2 = PQ.copy()
    uq2 = UQ.copy()
    
    res = checkIsomorphism(pq2, uq2)
    if res:
       #-----------------------#
       vprint(6,f"   In fact, {PQ.prefix} and {UQ.prefix} graph patterns are isomorphic.\033[0m")
       #-----------------------#
    else:
        #-----------------------#
        vprint(6,f"   But {PQ.prefix} and {UQ.prefix} graph patterns are not isomorphic.\033[0m")
        vprint(6)
        return {'compatible' : True, 'reason' : '', 'toCheck' : toCheck }
        #-----------------------#
  

    # PQ and UQ have the same time window definition
    #code for extracting aggregate and group variables
    
    for key, value in pq1.variables.items():
        if key==pq1.aggregate['variable']:
            pq1.aggregate['variable']=value
    
    for key, value in uq1.variables.items():
        if key==uq1.aggregate['variable']:
            value= value.replace("?","c_")
            uq1.aggregate['variable']=value
           
    GroupListPQ=[]
    for i,j in enumerate (pq1.group_by):
        for key, value in pq1.variables.items():
            if j==key:
                GroupListPQ.append(value)
    
    GPQ= ''
    for x,y in enumerate(GroupListPQ):
        if x==0 and x!=(len(GroupListPQ)-1):
            GPQ += '' +y
        if x!=0 and x!=(len(GroupListPQ)-1):
            GPQ += ', ' +y
        if x!=0 and x==(len(GroupListPQ)-1):
            GPQ += ' and ' +y
        if x==0 and x==(len(GroupListPQ)-1):
            GPQ += '' +y   
            
    current_time=datetime.now()    
    ct1=current_time.strftime('%m-%d-%Y %H:%M:%S')
    ct2=current_time - timedelta(hours=int(UQ.size))
    ct2=ct2.strftime('%m-%d-%Y %H:%M:%S')    
    GroupListUQ=[]
    ListUQ=[]
    for i,j in enumerate (uq1.group_by):
        for key, value in uq1.variables.items():
            if j==key:               
               GroupListUQ.append(value+'1')
    
    GroupListUQ= str(GroupListUQ).replace("?timeWindowEnd1",str(ct1))
    GroupListUQ= str(GroupListUQ).replace("?","")
    GroupListUQ= str(GroupListUQ).replace("'","")
    GroupListUQ= str(GroupListUQ).replace("[","(")
    GroupListUQ= str(GroupListUQ).replace("]","")
    GUQ= ''
    GUQ= GroupListUQ+', 8)' #when steps and sizes are same for SUM (first reading)
    GUQ1= GroupListUQ+', 5)' #when steps and sizes are same for MAX
    GUQ2= GroupListUQ+', 3)' #when steps and sizes are same for MIN
    GUQ3= GroupListUQ+', 2)' #when steps and sizes are same for COUNT
    GroupListUQ=str(GroupListUQ).replace(str(ct1), str(ct2))
    GUQ2= GroupListUQ+', 3)' #when steps and sizes are same for SUM (second reading)
    
    PQSA=[]    
    PQSSA=[]
    SuggPQSSA=[]
    for x,y in enumerate(list_APQ):
        for key, value in uq1.constants.items():
            if y==value:
                PQSA.append(key)
               
    for x,y in enumerate(PQSA):
        for key, value in uq1.variables.items():
            if y==key:
                PQSSA.append(value)
                SuggPQSSA.append(value)
                
    PQSSA=sorted(list(set(PQSSA)))
    SuggPQSSA=sorted(list(set(SuggPQSSA)))
    
    SuggPQSSA.remove('?timestamp')
    SuggPQSSA=str(SuggPQSSA).replace('[',"")
    SuggPQSSA=str(SuggPQSSA).replace(']',"")
                      
    
    
    PQALA=str(PQSSA).replace('?',"")
    PQALA=str(PQALA).replace("'","")
    PQALA=str(PQALA).replace('[',"")
    PQALA=str(PQALA).replace(']',"") 
    PQALA=str(PQALA).replace('timestamp',str(ct1))    
    PQALA1='(' +PQALA+ ', 8)' #for SUM  
    PQALA2='('+PQALA+', 3)' #for MIN
    PQALA3='('+PQALA+', 5)' #for MAX
    PQALA4='('+PQALA+', 2)' #for COUNT
    AUQs_GPL=[]
    AGUQs = readTACQs(mainArgs.utility, 'UQ')    
    
    t1=current_time - timedelta(hours=1)
    t1=t1.strftime('%m-%d-%Y %H:%M:%S')
    n=int(UQ.size)+1
    #print(n)
    t2=current_time - timedelta(hours=n)
    t2=t2.strftime('%m-%d-%Y %H:%M:%S')
    #print(t1, t2)
    for q in AGUQs.keys():        
        if q==UQ.prefix:
            AUQs_GPL.append(AGUQs[q].gp)
            
    for r in (AGUQs[q].gp):
        if (r['timestamp'][0])=='?':            
            AUQs_GPL=str(AUQs_GPL).replace(r['timestamp'], 'TS')
        if (r['subject'][0])=='?':
             AUQs_GPL=str(AUQs_GPL).replace(r['subject'],str(r['subject'])+'1')
               
    AUQs_GPL= str(AUQs_GPL).split()
    AUQs_GPL=str(AUQs_GPL).replace("'subject':","")
    AUQs_GPL=str(AUQs_GPL).replace("'object':","")
    AUQs_GPL=str(AUQs_GPL).replace("'predicate':","")        
    AUQs_GPL=str(AUQs_GPL).replace("'","")
    AUQs_GPL=str(AUQs_GPL).replace('"',"")
    AUQs_GPL=str(AUQs_GPL).replace('?',"c_")
    AUQs_GPL=str(AUQs_GPL).replace('{',"")
    AUQs_GPL=str(AUQs_GPL).replace('}',".")
    AUQs_GPL=str(AUQs_GPL).replace('[',"")
    AUQs_GPL=str(AUQs_GPL).replace(']',"")
    AUQs_GPL=str(AUQs_GPL).replace(',',"")
    AUQs_GPL=str(AUQs_GPL).replace("timestamp: any","")
    AUQs_GPL=str(AUQs_GPL).replace(" timestamp:",",")   
    AUQs_GPL=AUQs_GPL[1:-1]
    AUQs_GPL = '{'+AUQs_GPL+'}'
    AUQs_GPL=str(AUQs_GPL).replace(uq1.aggregate['variable'],"5")    
    AUQs_GPL1=str(AUQs_GPL).replace("5","3")
    AUQs_GPL=str(AUQs_GPL).replace('TS',str(t1))
    AUQs_GPL1=str(AUQs_GPL1).replace('TS',str(t2))
    AUQs_GPL=str(AUQs_GPL).replace('c_','')
    AUQs_GPL1=str(AUQs_GPL1).replace('c_','')
 
    
    
    if PQ.size == 'inf' and UQ.size == 'inf':
        #-----------------------#
       
        if PQ.aggregate['function'] in ['sum', 'SUM']:
            print(f"-> Answering {UQ.prefix} may provide the following answers:",file=outputfile)
            print(f"   {GUQ}",file=outputfile)      
            print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, these two consecutive answers to {UQ.prefix} can be combined to compute the following answer of {PQ.prefix}:",file=outputfile)
            print(f"   {PQALA1}<",file=outputfile) 
        elif PQ.aggregate['function'] in ['count', 'COUNT']:
            print(f"-> Answering {UQ.prefix} may provide the following answers:",file=outputfile)
            print(f"   {GUQ3}",file=outputfile)           
            print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, these two consecutive answers to {UQ.prefix} can be combined to compute the following answer of {PQ.prefix}:",file=outputfile)
            print(f"   {PQALA4}<",file=outputfile) 
        elif PQ.aggregate['function'] in ['min', 'MIN']:
            print(f"-> Answering {UQ.prefix} may provide the following answers:",file=outputfile)
            print(f"   {GUQ2}",file=outputfile)         
            print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, these two consecutive answers to {UQ.prefix} can be combined to compute the following answer of {PQ.prefix}:",file=outputfile)
            print(f"   {PQALA2}<",file=outputfile) 
        else:
            print(f"-> Answering {UQ.prefix} may provide the following answers:",file=outputfile)
            print(f"    {GUQ1}",file=outputfile)          
            print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, these two consecutive answers to {UQ.prefix} can be combined to compute the following answer of {PQ.prefix}:" ,file=outputfile)
            print(f"   {PQALA3}<",file=outputfile)   
        print(f"Answering the tility Query {UQ.prefix} can reveal answers of privacy query {PQ.prefix}.",file=outputfile)       
        vprint(6,f"   Finally, {PQ.prefix} and {UQ.prefix} have the same time window definition.")
        vprint(6)
        #-----------------------#

        return { 'compatible' : False, 'reason' : f"Results for all time windows of {PQ.prefix} can be built from results for time windows of {UQ.prefix}.", 'toCheck' : toCheck }

    
    if PQ.size == UQ.size and PQ.size != 'inf':
        #-----------------------#
             
        if PQ.aggregate['function'] in ['sum', 'SUM']:
            print(f"-> Answering {UQ.prefix} may provide the following answers:",file=outputfile)
            print(f"    {GUQ}",file=outputfile)           
            print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, the answers to {UQ.prefix} can compute the following answer of {PQ.prefix}: ",file=outputfile)
            print(f"    {PQALA1}<",file=outputfile)           
        elif PQ.aggregate['function'] in ['count', 'COUNT']:
            print(f"-> Answering {UQ.prefix} may provide the following answers:",file=outputfile)
            print(f"     {GUQ3}",file=outputfile)            
            print(f"-> As {UQ.prefix} and {PQ.prefix} compute same aggregate so answers of {PQ.prefix} can be used to computed, namely:",file=outputfile)
            print(f"     {PQALA4}<",file=outputfile)
        elif PQ.aggregate['function'] in ['min', 'MIN']:
            print(f"-> Answering {UQ.prefix} may provide the following answers:",file=outputfile)
            print(f"     {GUQ2}",file=outputfile)    
            print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, the answers to {UQ.prefix} can be used to compute the following answer of {PQ.prefix}: ",file=outputfile)
            print(f"     {PQALA2}<",file=outputfile)
        else:
            print(f"-> Answering {UQ.prefix} may provide the following answers:",file=outputfile)
            print(f"     {GUQ1}",file=outputfile)           
            print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, the answers to {UQ.prefix} can be used to compute the following answer of {PQ.prefix}: ",file=outputfile)
            print(f"     {PQALA3}<",file=outputfile)           
        print(f"Answering the utility Query {UQ.prefix} can reveal answers of privacy query {PQ.prefix}.",file=outputfile)
        print(f"{PQ.prefix} is not compatible with {UQ.prefix}.",file=outputfile)
        

        vprint(6,f"   Finally, {PQ.prefix} and {UQ.prefix} have the same time window definition.")
        vprint(6)
        #-----------------------#

        return { 'compatible' : False, 'reason' : f"Results for all time windows of {PQ.prefix} can be built from results for time windows of {UQ.prefix}.", 'toCheck' : toCheck }


    # PQ and UQ have different time window definitions
    else:
        #-----------------------#
        vprint(6,f"   \033[33m{PQ.prefix} still MAY BE INCOMPATIBLE with {UQ.prefix} !\033[0m")
        vprint(6)
        #-----------------------#
        toCheck = True

        ## SUM or COUNT
        
        if PQ.aggregate['function'] in ['sum', 'SUM', 'count', 'COUNT']:
            if UQ.size == 'inf':
                #-----------------------#
                vprint(6,f"   But no time window of {PQ.prefix} can be built by disjoint union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
                #-----------------------#
                return { 'compatible' : True, 'reason' : '', 'toCheck' : toCheck }

            m = int(UQ.size) / int(UQ.step)
            if m-int(m) != 0:
                #-----------------------#
                vprint(6,f"   But no time window of {PQ.prefix} can be built by disjoint union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
                #-----------------------#
                return { 'compatible' : True, 'reason' : '', 'toCheck' : toCheck }

            if PQ.size == 'inf':
                
                #-----------------------#
                print(f"Data graph: {AUQs_GPL}",file=outputfile)
                print(f"                     {AUQs_GPL1}",file=outputfile)        
                if PQ.aggregate['function'] in ['sum', 'SUM']:
                    print(f"-> Answer set for {UQ.prefix} computed for each time window over data graph: {GUQ1}",file=outputfile)
                    print(f"-> Answer set for {PQ.prefix} computed for each time window over data graph: {PQALA1}<",file=outputfile)
                else:
                    print(f"-> Answer set for {UQ.prefix} over data graph: {GUQ2}",file=outputfile)
                    print(f"-> Answer set for {PQ.prefix} over data graph: {PQALA2}<",file=outputfile)                
                vprint(6,f"   Finally, the time window of {PQ.prefix} can be built by disjoint union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
                #-----------------------#
                return { 'compatible' : False, 'reason' : f"Aggregate results computed over every time window of {PQ.prefix} can be built from aggregate results of time windows of {UQ.prefix}.", 'toCheck' : toCheck }

            n = int(PQ.size) / int(UQ.size)
            if n - int(n) != 0:
                #-----------------------#
                vprint(6, f"   But no time window of {PQ.prefix} can be built by disjoint union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
                #-----------------------#
                return { 'compatible' : True, 'reason' : '', 'toCheck' : toCheck }
            
            #-----------------------#
             
            if PQ.aggregate['function'] in ['sum', 'SUM']:
                
                print(f"-> Answering {UQ.prefix} over two contiguous time windows that cover exactly a time window of {PQ.prefix}, may provide the following answers:",file=outputfile)
                print(f"    {GUQ1}",file=outputfile)
                print(f"    {GUQ2}",file=outputfile)               
                print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, these two consecutive answers to {UQ.prefix} can be combined to compute the following answer of {PQ.prefix}: ",file=outputfile)
                print(f"    {PQALA1}<",file=outputfile)
                print(f"Choose one of the following options to reduce the privacy risk raised by the privacy query {PQ.prefix}:",file=suggestionsfile) 
                if len(SuggPQSSA)!=0:
                    print(f"Remove '{SuggPQSSA}' from the output {UQ.prefix}!",file=suggestionsfile)                                
                print(f"Replace the aggregate 'SUM' with the aggregate 'MAX' or 'MIN' {UQ.prefix}!",file=suggestionsfile)             
                print(f"Modify the size or the step defined in the time window {UQ.prefix}!",file=suggestionsfile)              
                print(">",file=suggestionsfile)
                
            else:
                print(f"-> Answering {UQ.prefix} over two contiguous time windows that cover exactly a time window of {PQ.prefix}, may provide the following answers:",file=outputfile)
                print(f"     {GUQ1}",file=outputfile)
                print(f"     {GUQ2}",file=outputfile)              
                print(f"-> As {UQ.prefix} and {PQ.prefix} compute the same aggregate, these two consecutive answers to {UQ.prefix} can be combined to compute the following answer of {PQ.prefix}: ",file=outputfile)
                print(f"    {PQALA4}<",file=outputfile)             
            print(f"Img-SC.jpg",file=outputfile)
            print(f"Answering the utility query {UQ.prefix} can reveal some answers of privacy query {PQ.prefix}.",file=outputfile)      
            
            vprint(6, f"   Finally, all the time windows of {PQ.prefix} can be built by disjoint union of time windows of {UQ.prefix}.\033[0m")
            vprint(6)
            #-----------------------#
            return { 'compatible' : False, 'reason' : f"Aggregate results computed over every time window of {PQ.prefix} can be built from aggregate results of time windows of {UQ.prefix}.", 'toCheck' : toCheck }


        ## MIN or MAX
        if PQ.aggregate['function'] in ['min', 'MIN', 'max', 'MAX']:
            if UQ.size == 'inf':
                #-----------------------#
                vprint(6,f"   But no time window of {PQ.prefix} can be built by union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
                #-----------------------#
                return { 'compatible' : True, 'reason' : '', 'toCheck' : toCheck }

            m = int(UQ.size) < int(UQ.step)
            if m-int(m) != 0:
                #-----------------------#
                vprint(6,f"   But no time window of {PQ.prefix} can be built by union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
                #-----------------------#
                return { 'compatible' : True, 'reason' : '', 'toCheck' : toCheck }

            if PQ.size == 'inf':
                #-----------------------#
                print(f"Data graph: {AUQs_GPL}",file=outputfile)
                print(f"                     {AUQs_GPL1}",file=outputfile)        
                if PQ.aggregate['function'] in ['min', 'MIN']:
                    print(f"-> Answer set for {UQ.prefix} over data graph: {GUQ2}",file=outputfile)
                    print(f"-> Answer set for {PQ.prefix} over data graph: {PQALA2}<",file=outputfile)
                else:
                    print(f"-> Answer set for {UQ.prefix} over data graph: {GUQ3}",file=outputfile)
                    print(f"-> Answer set for {PQ.prefix} over data graph: {PQALA3}<",file=outputfile)
                print(f"Utility Query {UQ.prefix} can reveal answers of privacy query {PQ.prefix}.",file=outputfile)                
                vprint(6,f"   Finally, the time window of {PQ.prefix} can be built by union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
                #-----------------------#
                return { 'compatible' : False, 'reason' : f"Aggregate results computed over every time window of {PQ.prefix} can be built from aggregate results of time windows of {UQ.prefix}.", 'toCheck' : toCheck }

            n = (int(PQ.size) - int(UQ.size)) / int(UQ.size)
            if n - int(n) != 0:
                #-----------------------#
                vprint(6, f"   But no time window of {PQ.prefix} can be built by union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
                #-----------------------#
                return { 'compatible' : True, 'reason' : '', 'toCheck' : toCheck }
            
            #-----------------------#
                vprint(6, f"   Finally, all the time windows of {PQ.prefix} can be built by union of time windows of {UQ.prefix}.\033[0m")
                vprint(6)
            print(f"Data graph: {AUQs_GPL}",file=outputfile)
            print(f"                     {AUQs_GPL1}",file=outputfile)        
            if PQ.aggregate['function'] in ['min', 'MIN']:
                print(f"-> Answering {UQ.prefix} over two continguous or overlapping time windows Tu that cover exactly a time window Tp of {PQ.prefix}, may provide the following answers:",file=outputfile)
                print(f"    {GUQ1}",file=outputfile)
                print(f"    {GUQ2}",file=outputfile)                
                print(f"-> As {UQ.prefix} and {PQ.prefix} compute same aggregate so answers of {PQ.prefix} can be computed for a covered time window Tp, namely: ",file=outputfile)
                print(f"    {PQALA2}<",file=outputfile)  
    
            else:
                print(f"-> Answering {UQ.prefix} over two continguous or overlapping time windows Tu of that cover exactly a time window Tp of {PQ.prefix}, may provide the following answers:",file=outputfile)
                print(f"    {GUQ1}",file=outputfile)
                print(f"    {GUQ2}",file=outputfile)              
                print(f"-> As {UQ.prefix} and {PQ.prefix} compute same aggregate so answers of {PQ.prefix} can be computed for a covered time window Tp, namely: ",file=outputfile)
                print(f"    {PQALA3}<",file=outputfile)            
            print(f"Img-SC.jpg",file=outputfile)           
            print(f"Utility Query {UQ.prefix} can reveal answers of privacy query {PQ.prefix}.",file=outputfile)
            
            #-----------------------#
            return { 'compatible' : False, 'reason' : f"Aggregate results computed over every time window of {PQ.prefix} can be built from aggregate results of time windows of {UQ.prefix}.", 'toCheck' : toCheck }




def checkAggregateCompatibility2UQ(PQ, UQ1, UQ2):
    """
    Checks compatibility of one PQ and two UQs computing the same aggregate.

    Verbose level: 7

    inputs: - PQ -> original privacy TACQ with prefix
            - UQ1 -> a utility TACQ whose graph pattern is isomorphic to graph pattern of PQ and have same aggregate but different time windows as of PQ  
            - UQ2 -> another utility TACQ whose graph pattern is isomorphic to graph pattern of PQ and have same aggregate but different time windows as of PQ 
    output: - a dictionary { compatible, reasons }
                - compatible: boolean
                - reason: a summary of the explaination if incompatible
    """
    #code for extracting aggregate and group variables    
    for key, value in PQ.variables.items():
        if key==PQ.aggregate['variable']:
            PQ.aggregate['variable']=value
    GroupListPQ2=[]
    for i,j in enumerate (PQ.group_by):
        for key, value in PQ.variables.items():
            if j==key:
                GroupListPQ2.append(value)
    GPQ2= ''
    for x,y in enumerate(GroupListPQ2):
        if x==0 and x!=(len(GroupListPQ2)-1):
            GPQ2 += '' +y
        if x!=0 and x!=(len(GroupListPQ2)-1):
            GPQ2 += ', ' +y
        if x!=0 and x==(len(GroupListPQ2)-1):
            GPQ2 += ' and ' +y
        if x==0 and x==(len(GroupListPQ2)-1):
            GPQ2 += '' +y
    
            
    
    GroupListUQ1=[]
    for i,j in enumerate (UQ1.group_by):
        for key, value in UQ1.variables.items():
            if j==key:
               GroupListUQ1.append(value)

    GUQ1= ''
    for x,y in enumerate(GroupListUQ1):
        if x==0 and x!=(len(GroupListUQ1)-1):
            GUQ1 += '' +y
        if x!=0 and x!=(len(GroupListUQ1)-1):
            GUQ1 += ', ' +y
        if x!=0 and x==(len(GroupListUQ1)-1):
            GUQ1 += ' and ' +y
        if x==0 and x==(len(GroupListUQ1)-1):
            GUQ1 += '' +y   
               

    for key, value in UQ1.variables.items():
        if key==UQ1.aggregate['variable']:
            UQ1.aggregate['variable']=value

    GroupListUQ2=[]
    for m,n in enumerate (UQ2.group_by):
        for key, value in UQ2.variables.items():
            if n==key:
               GroupListUQ2.append(value)

    GUQ2= ''
    for x,y in enumerate(GroupListUQ2):
        if x==0 and x!=(len(GroupListUQ2)-1):
            GUQ2 += '' +y
        if x!=0 and x!=(len(GroupListUQ2)-1):
            GUQ2 += ', ' +y
        if x!=0 and x==(len(GroupListUQ2)-1):
            GUQ2 += ' and ' +y
        if x==0 and x==(len(GroupListUQ2)-1):
            GUQ2 += '' +y 
                   

    for key, value in UQ2.variables.items():
        if key==UQ2.aggregate['variable']:
            UQ2.aggregate['variable']=value
    
    ## when size of any query is infinite then conditions cannot be applied/satisfied
    if PQ.size == 'inf' or UQ1.size == 'inf' or UQ2.size == 'inf':
        #-----------------------#
        vprint(7,f"   No time window of {PQ.prefix} can be built by union of time windows of {UQ1.prefix} and {UQ2.prefix}.\033[0m")
        vprint(7)
        #-----------------------#
        return {'compatible' : True, 'reason' : ''}

    ## Checking first condition of incompatibility 
    ### For SUM and COUNT
    if PQ.aggregate['function'] in ['sum', 'SUM', 'count', 'COUNT']:
        if int(PQ.size) != (int(UQ1.size) + int(UQ2.size)):
            #-----------------------#
            vprint(7,f"   No time window of {PQ.prefix} can be built by disjoint union of time windows of {UQ1.prefix} and {UQ2.prefix}.\033[0m")
            vprint(7)
            #-----------------------#
            return {'compatible' : True, 'reason' : ''}
    ### For MIN and MAX
    if PQ.aggregate['function'] in ['min', 'MIN', 'max', 'MAX']:
        if int(PQ.size) > (int(UQ1.size) + int(UQ2.size)):
            #-----------------------#
            vprint(7,f"   No time window of {PQ.prefix} can be built by union of time windows of {UQ1.prefix} and {UQ2.prefix}.\033[0m")
            vprint(7)
                #-----------------------#
            return {'compatible' : True, 'reason' : ''}
             
    ## Computing the values needed to check the second condition of incompatibility
    sigma_p = int(PQ.step)/math.gcd(int(PQ.step), int(UQ2.step))
    gcd     = math.gcd(int(UQ1.step), (int(sigma_p)*int(UQ2.step)))
    n       = (int(PQ.size)-int(UQ1.size))/int(gcd)

    ## Checking second condition of incompatibility
    if n - int(n) != 0:
        #-----------------------#
        vprint(7, f"   No time window of {PQ.prefix} can be built by disjoint union of time windows of {UQ1.prefix} and {UQ2.prefix}.\033[0m")
        vprint(7)
        #-----------------------#
        return {'compatible' : True, 'reason' : ''}           
        
    ## Finding the integer solution for variables using diophantine equation solver 
    sigma_uq2 = int(UQ2.step)/math.gcd(int(PQ.step), int(UQ2.step))
    x,y       = symbols("x, y", integer=True)
    int_sol   = diophantine((int(UQ1.step)*x) - (int(sigma_p)*int(UQ2.step)*y) - (int(PQ.size)-int(UQ1.size)))

    ## Computing minimum value for kp
    sol = str(int_sol)
    k = sol.split(",", 1)[1].split(")", 1)[0]

    kp_min = -1
    i = 0
    while kp_min < 0:
        l = k.replace('t_0', str(i))
        k0 = eval(l)
        kp_min= int(k0) * int(sigma_uq2)

    ## Computing smallest time window for PQ that can be built from the disjoint union of time windows of utility queries      
    tw = kp_min+1
    print(f"-> Graph patterns of {PQ.prefix}, {UQ1.prefix} and {UQ2.prefix} are same.",file=outputfile)
    print(f"-> Same '{PQ.aggregate['function']}' aggregate  on same variables ({PQ.aggregate['variable']} in {PQ.prefix}, {UQ1.aggregate['variable']} in {UQ1.prefix} and {UQ2.aggregate['variable']} in {UQ2.prefix}).",file=outputfile)
    print(f"-> Groups of {PQ.prefix} (on {GPQ2}) are included in groups of {UQ1.prefix} (on {GUQ1}) and {UQ2.prefix} (on {GUQ2}).",file=outputfile)
    print(f"-> Time Windows are incompatible so the smallest time window i.e '{tw}' of {PQ.prefix} (i.e., ]now-{kp_min*int(PQ.step)+int(PQ.size)}, now-{kp_min*int(PQ.step)}]) can be built by disjoint union of time windows of {UQ1.prefix} and {UQ2.prefix}.<",file=outputfile)
    print(f"Aggregate results for time windows of {PQ.prefix} can be built from aggregate results of time windows of {UQ1.prefix} and {UQ2.prefix}.",file=outputfile)
                                  
    #-----------------------#        
    vprint(7, f"   The smallest time window number i.e '{tw}' of {PQ.prefix} (i.e., ]now-{kp_min*int(PQ.step)+int(PQ.size)}, now-{kp_min*int(PQ.step)}]) can be built by disjoint union of time windows of {UQ1.prefix} and {UQ2.prefix}.\033[0m")
    vprint(7)
    #-----------------------#
    return {'compatible' : False, 'reason' : f"Aggregate results computed over time windows of {PQ.prefix} can be built from aggregate results of time windows of {UQ1.prefix} and {UQ2.prefix}."}

    

def printQueryResults(results, vars):
    """
    Prints the result of q SAPRQL query (RDFlib)

    inputs: - results -> query results
            - vars    -> list of var names
    output: - None
    """
    if not isinstance(vars, list):
        raise TypeError('The parameter "vars" of printQueryResults() must be a list of var names !')

    # size of line numbers
    lnb = len(str(len(results)))
        
    # size of var names
    lv = [len(v) for v in vars]

    # header
    header1 = '+-' + '-'*lnb + '-+-'
    header2 = '| ' + f"{'#':{lnb}}" + ' | '
    for v in range(len(vars)):
        header1 = header1 + '-' * lv[v] + '-+-'
        header2 = header2 + f"{vars[v]:{lv[v]}}" +' | '
    print(header1[:-1])
    print(header2[:-1])
    print(header1[:-1])

    # content
    nb = 1
    for res in results:
        line = '| ' + f"{nb:{lnb}}" + ' | '
        for v in range(len(vars)):
            line = line + f"{res[v]:{lv[v]}}" + ' | '
        print(line[:-1])
        nb = nb +1
    print(header1[:-1])
    


def get_cmd_line_args():
    """
    Parse the command line to get parameters.
    
    input:  - none
    output: - a Namespace containing parameter values
    """
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-p', '--privacy', help = 'file containing the privacy queries', default = resource_path('PQs.sparql'))
    parser.add_argument('-u', '--utility', help = 'file containing the utility queries', default = resource_path('UQs.sparql'))
    parser.add_argument('-v', '--verbose', help = 'levels of details', default="0")
    return parser.parse_args()



def vprint(filter='0', *args):
    """
    Prints arguments if Verbose is on.

    inputs: - something to print
    output: - None
    """
    if str(filter) in mainArgs.verbose or str(filter) == '0':
        for i in list(args):
            print(str(i), end=" ")
        print()

    
mainArgs = get_cmd_line_args()

def main():
    """
    Main function implementing the chain of tests
    """

    # Arguments
    
    #-----------------------#
    vprint(0,'\033[1;34m----------\033[0m')
    vprint(0,'\033[1;34mArguments:\033[0m')
    vprint(0,'\033[1;34m----------\033[0m')
    vprint(0,'Privacy file:', mainArgs.privacy)
    vprint(0,'Utility file:', mainArgs.utility)
    if mainArgs.verbose != '0':
        vprint(0,f"Verbose is {mainArgs.verbose}.")
    else:
        vprint(0,'Verbose is off.')
    vprint(0)
    #-----------------------#
    global outputfile
    outputfile = open(resource_path("output.txt"), "w")

    global suggestionsfile
    suggestionsfile = open(resource_path("suggestions.txt"), "w")

    # Privacy queries
    origPQs = {}
    PQs = readTACQs(mainArgs.privacy, 'PQ')
    
    for q in PQs.keys():
        origPQs.update({q : PQs[q].copy()})
        origPQs[q].renameVariables(prefix=q)

    #-----------------------#
    vprint(1,'\033[1;34m----------------\033[0m')
    vprint(1,'\033[1;34mPrivacy queries:\033[0m')
    vprint(1,'\033[1;34m----------------\033[0m')
    for q in PQs.keys():
        vprint(1,q, ':')
        vprint(1,PQs[q].toString())
        vprint(1)
    #-----------------------#

    # Rename variables and extract joins from privacy queries
    for q in PQs.keys():
        PQs[q].renameVariables(prefix=q)
        PQs[q].extractJoins()

    for q in origPQs.keys():
        print(q, ':', origPQs[q].toString())
        print()
    
    #-----------------------#
    vprint(1,'--------------------------')
    vprint(1,'Rewritten privacy queries:')
    vprint(1,'--------------------------')
    for q in PQs.keys():
        vprint(1,q, ':')
        vprint(1,PQs[q].toString())
        if '1' in mainArgs.verbose:
            PQs[q].printVariables()
        vprint(1,)
    #-----------------------#

    # Reify privacy queries

    #-----------------------#
    vprint(1,'------------------------')
    vprint(1,'Reified privacy queries:')
    vprint(1,'------------------------')
    #-----------------------#

    for q in PQs.keys():
        PQs[q].reify()

    #-----------------------#
    for q in PQs.keys():
        vprint(1,q, ':')
        vprint(1,PQs[q].toString())
        vprint(1)
    #-----------------------#
    
    # Utility queries
    origUQs = {}
    global UQs
    UQs = readTACQs(mainArgs.utility, 'UQ')
    for q in UQs.keys():
        origUQs.update({q : UQs[q].copy()})
        origUQs[q].renameVariables(prefix=q)
   
        
    #-----------------------#
    vprint(1,'\033[1;34m----------------\033[0m')
    vprint(1,'\033[1;34mUtility queries:\033[0m')
    vprint(1,'\033[1;34m----------------\033[0m')
    
    for q in UQs.keys():
        vprint(1,q, ':')
        vprint(1,UQs[q].toString())
        vprint(1)
  
    
               
    #-----------------------#
    
    # Rename variables of utility queries
    for q in UQs.keys():
        UQs[q].renameVariables(prefix=q)
  
    #-----------------------#
    vprint(1,'--------------------------')
    vprint(1,'Rewritten utility queries:')
    vprint(1,'--------------------------')
    for q in UQs.keys():
        vprint(1,q, ':')
        vprint(1,UQs[q].toString())
        if '1' in mainArgs.verbose:
            UQs[q].printVariables()
        vprint()
    #-----------------------#

    # Reify utility queries
    for q in UQs.keys():
        UQs[q].reify()

    #-----------------------#
    vprint(1,'------------------------')
    vprint(1,'Reified utility queries:')
    vprint(1,'------------------------')
    for q in UQs.keys():
        vprint(1,q, ':')
        vprint(1,UQs[q].toString())
        vprint(1)
    #-----------------------#


    # Compute union of utility query graph patterns
    unionUQs = TACQ()
    for q in UQs.keys():
        unionUQs = unionUQs.union(UQs[q])

    #-----------------------#
    vprint(2,'\033[1;34m-------------------------------------------\033[0m')
    vprint(2,'\033[1;34mUnion of graph patterns of Utility Queries:\033[0m')
    vprint(2,'\033[1;34m-------------------------------------------\033[0m')
    vprint(2,unionUQs.toString('wj')[8:-2])
    vprint(2)
    #-----------------------#


    # For each pricavy query
    compatibility = 'True'
    for q in PQs.keys():
        comp = 'True'
        #-----------------------#
        vprint(1,'\033[33m  ','='*(len(q)+14),'\033[0m')
        vprint(1,'\033[33m  ','Testing query',q,'\033[0m')
        vprint(1,'\033[33m  ','='*(len(q)+14),'\033[0m')
        vprint(1)
        #-----------------------#

        ## Check inclusion of graph patterns

        #-----------------------#
        vprint(3,'\033[1;34m   ==========================================================================\033[0m')
        vprint(3,'\033[1;34m   Checking inclusion of PQ graph pattern into the union of UQ graph patterns\033[0m')
        vprint(3,'\033[1;34m   ==========================================================================\033[0m')
        vprint(3)
        #-----------------------#

        res = checkGraphPatternOverlap(PQs[q], unionUQs)        
                    
        
        if res['compatible']:
            vprint(1,f"\033[1;33m   The graph pattern of privacy query {PQs[q].prefix} is not included into the union of graph patterns of utility queries.\033[0m")
            vprint(1)
            vprint(1,f"\033[1;32m   Privacy query {q} is compatible with the utility policy.\033[1;37\033[0m")
            vprint(1)
        else:
                        
            if PQs[q].isConjunctive():            
                vprint()
              
                #-----------------------#
                if PQs[q].joins:                    
                    print(f"-> Answering utility queries may provide the following answers:",file=outputfile)
                    if len(ReasonsJoins)!=0:                        
                        for r in ReasonsJoins:                    
                            print(r,file=outputfile)                            
                        print(f"-> Thus revealing the presence of the following facts in the data:",file=outputfile)
                        print(f"    {UQs_GPLJ}",file=outputfile)
                        print(f"-> From which an answer of {PQs[q].prefix} can be deduced, namely: {PQASS}<",file=outputfile)                                              
                        print(f"Answering the two utility queries {UQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)                    
                        print(f"Choose one of the following options to reduce the privacy risk raised by the privacy query {PQs[q].prefix}:",file=suggestionsfile)
                        for s in OutputConj:
                            print(s,file=suggestionsfile)
                        for t in OutputGen:
                            print(t,file=suggestionsfile)
                        print(">",file=suggestionsfile)
                      
                                                
                    else:
                                                
                        for r in ReasonsJoinsConj:                    
                            print(r,file=outputfile)                        
                        print(f"-> Thus revealing the presence of the following facts in the data:",file=outputfile)
                        print(f'    {UQs_GPLJ}',file=outputfile)
                        print(f"-> From which an answer of {PQs[q].prefix} can be deduced, namely: {PQAL}<",file=outputfile)
                                          
                        if len(CUQLL)==1:
                            print(f"Answering the utility query {CUQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)
                            for s in OutputConj:
                                print(s)
                        
                        else:
                            print(f"Answering the two utility queries {UQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)                            
                            for s in OutputConj:
                                print( s)
                            print(f" {outputJoins} in {SUQL}")
                else:
                    print(f"-> Answering utility queries may provide the following answers:",file=outputfile)                   
                    for r in ReasonsJoinsConj:                    
                            print(r,file=outputfile)
                    print(f"-> Thus revealing the presence of the following facts in the data:",file=outputfile)
                    print(f'    {UQs_GPL}',file=outputfile)
                    print(f"-> From which an answer of {PQs[q].prefix} can be deduced, namely: {PQAL}<",file=outputfile)                   
                    if len(CUQLL)==1:
                        print(f"Answering the utility query {CUQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)
                       
                        print(f"Choose one of the following options to reduce the privacy risk raised by the privacy query {PQs[q].prefix}:",file=suggestionsfile)
                        for s in OutputConj:
                            print(s,file=suggestionsfile)
                        for t in OutputGen:
                            print(t,file=suggestionsfile)
                        print(">",file=suggestionsfile)
                       
                            
                    else:
                        print(f"Answering the two utility queries {UQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)
                       
                
                vprint(1)
                vprint(1,f"\033[1;33m   The graph pattern of the plain conjunctive privacy query {PQs[q].prefix} can be included into the union of graph patterns of utility queries by joining some output variables.\033[0m")
                vprint(1)
                vprint(1,f"\033[1;31m   Privacy query {q} IS NOT COMPATIBLE with utility policy !\033[0m")
                vprint(1)
                #-----------------------#
                comp = 'False'
            # TACQ => sufficient condition
            else:
                #-----------------------#
                for r in res['reasons']:
                    vprint(3,'\033[1;33m  ',r,'\033[0m')
                vprint(1,f"\033[1;33m   The graph pattern of privacy query {PQs[q].prefix} can be included into the union of graph patterns of utility queries by union of some output variables.\033[0m")
                vprint(1)
                vprint(1,f"\033[33m   Privacy query {q} MAY NOT BE COMPATIBLE with utility policy !\033[0m")
                vprint(1,'\033[33m   Filter conditions have to be checked...\033[0m')
                vprint(1)
                #-----------------------#
                if comp != 'False':
                    comp = 'Maybe'

        #-----------------------#
        vprint(3)
        #-----------------------#

        ## Check Filter conjunction
        if comp == 'Maybe':
            comp = 'True'

            #-----------------------#
            vprint(4,'\033[1;34m   ================================================================================================\033[0m')
            vprint(4,'\033[1;34m   Satisfiability checking of conjunction of Filter conditions of privacy query and utility queries\033[0m')
            vprint(4,'\033[1;34m   ================================================================================================\033[0m')
            vprint(4)
            #-----------------------#

            if not PQs[q].filter:
                v = list(PQs[q].variables.keys())[0]
                PQs[q].filter = [{'opl' : v, 'comp' : '=', 'opr' : v}]
             
                                
            res = checkFilterConjunctionSatisfiability(PQs[q], unionUQs, res['results'])
            if res['compatible']:
                #-----------------------#
                vprint(1,"\033[1;33m   The filter expression is not satisfiable.\033[0m")
                vprint(1)
                vprint(1,f"\033[1;32m   Privacy query {q} is compatible with utility policy.\033[0m ")
                vprint(1)
                #-----------------------#
            else:
                #-----------------------#
                line = ''
                for n in res['reasons']:
                    line = line + str(n) +", "
                if '4' in mainArgs.verbose:
                    vprint(1,"\033[1;33m   The filter expression is satisfiable for result line(s)", line[:-2], '.\033[0m')
                else:
                    if not PQs[q].aggregate:
                        vprint(1,"\033[1;33m   The filter expression is satisfiable.\033[0m")
                        if PQs[q].joins:                           
                            print(f"-> Answering utility queries may provide the following answers:",file=outputfile)
                            if len(ReasonsJoins)!=0:
                                for r in ReasonsJoinsF:                    
                                    print(r,file=outputfile)
                                    print(outputJoins)
                                print(f"-> Thus revealing the presence of the following facts in the data:",file=outputfile)
                                print(f"    {UQs_GPLG}",file=outputfile)
                                print(f"-> From which an answer of {PQs[q].prefix} can be deduced, namely: {PQASSF}<",file=outputfile)                               
                                print(f"Answering the two utility queries {UQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)
                               
                            else:
                                for r in ReasonsJoinsConjF:                    
                                    print(r,file=outputfile)
                                print(f"-> Thus revealing  the presence of the following facts in the data:",file=outputfile)
                                print(f"    {UQs_GPLG}",file=outputfile)
                                print(f"-> From which an answer of {PQs[q].prefix} can be deduced, namely: {PQALF}<",file=outputfile)
                                                       
                                if len(CUQLL)==1:
                                    print(f"Answering the utility query {CUQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)                                   
                                else:
                                    print(f"Answering the two utility queries {UQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)
                                  
                        else:
                           
                            print(f"-> Answering utility queries may provide the following answers:",file=outputfile)
                            for r in ReasonsJoinsConjF:                    
                                print(r,file=outputfile)
                            print(f"-> Thus revealing the presence of the following facts in the data:",file=outputfile)
                            print(f"    {UQs_GPLG}",file=outputfile)
                            print(f"-> From which an answer of {PQs[q].prefix} can be deduced: {PQALF}<",file=outputfile)                           
                            if len(CUQLL)==1:
                                print(f"Answering the utility query {CUQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)                             
                            else:
                                print(f"Answering the two utility queries {UQL} can reveal some answers of privacy query {PQs[q].prefix}.",file=outputfile)
                                
                        
                    
                    vprint(1)
                if PQs[q].aggregate:
                    #-----------------------#
                    vprint(1,f"\033[33m   Privacy query {q}, containing aggregates computation, MAY NOT BE COMPATIBLE with utility policy !\033[0m")
                    vprint(1,"\033[33m   Aggregate functions and time windows have to be checked...\033[0m")
                    vprint(1)
                    #-----------------------#
                    if comp != 'False':
                        comp = 'Maybe'
                else:
                    #-----------------------#
                    vprint(1,f"\033[1;31m   Privacy query {q}, containing no aggregate computation, IS WEAKLY INCOMPATIBLE with utility policy !\033[0m")
                    vprint(1)
                    #-----------------------#
                    comp = 'False'


        ## Check aggregate and time windows with each utility query

        UQsToCheck = []         # list of UQs to be checked two by two (or more ?)

        if comp == 'Maybe':
            comp = 'True'
            #-----------------------#
            vprint(6, "\033[1;34m   ==================================================================================================\033[0m")
            vprint(6, "\033[1;34m   Checking compatibility of aggregate computation and time window definition with each utility query\033[0m")
            vprint(6, "\033[1;34m   ==================================================================================================\033[0m")
            vprint(6)
            #-----------------------#

            ## original PQ
            PQ = origPQs[q]
            PQ.prefix = q
            
            # For each UQ
            for uq in origUQs.keys():
                vprint(6, '   \033[1;33m----------------------\033[0m')
                vprint(6,f"   \033[1;33mTesting {q} versus {uq}\033[0m")
                vprint(6, '   \033[1;33m----------------------\033[0m')
                vprint(6)

                UQ = origUQs[uq]
                UQ.prefix = uq

                res = checkAggregateCompatibility1UQ(PQ, UQ)
                if not res['compatible']:
                    #-----------------------#
                  #if not '6' in mainArgs.verbose:
                    vprint(1, '\033[1;33m   ' + res['reason'])
                    vprint(1)
                    vprint(1, f"\033[1;31m   Privacy query {PQ.prefix} IS NOT COMPATIBLE with utility query {UQ.prefix} !\033[0m")                   
                    vprint(1)
                    #-----------------------#
                    comp = 'False'
                else:
                    if res['toCheck']:
                        UQsToCheck.append(UQ)
                    #-----------------------#
                    vprint(6, f"\033[1;32m   Privacy query {PQ.prefix} and utility query {UQ.prefix} are compatible.\033[0m")
                    vprint(6)
                    #-----------------------#
            
            if comp == 'True':
                if len(UQsToCheck) < 2:
                    #-----------------------#
                    vprint(1, f"\033[1;32m   Privacy query {PQ.prefix} is compatible with the utility policy.\033[0m")
                    vprint(1)
                    #-----------------------#
                else:
                    #-----------------------#
                    vprint(1, f"\033[1;33m   Privacy query {PQ.prefix} is compatible with each utility query individually.\033[0m")
                    vprint(1)
                    vprint(1, f"\033[33m   But it has to be checked against each pairs of relevant utility queries...\033[0m")
                    vprint(1)
                    #-----------------------#

                    #-----------------------#
                    vprint(7, "\033[1;34m   ============================================================================================================\033[0m")
                    vprint(7, "\033[1;34m   Checking compatibility of aggregate computation and time window definition with each pair of utility queries\033[0m")
                    vprint(7, "\033[1;34m   ============================================================================================================\033[0m")
                    vprint(7)
                    #-----------------------#


                    # Loop for taking two utility queries as an input
                    for i1 in range(0, len(UQsToCheck)-1):
                        for i2 in range(i1+1, len(UQsToCheck)):
                            UQ1 = UQsToCheck[i1]
                            UQ2 = UQsToCheck[i2]
                            #-----------------------#
                            vprint(7, '   \033[1;33m------------------------------------------------------\033[0m')
                            vprint(7,f"   \033[1;33mTesting {q} versus the pair {UQ1.prefix} and {UQ2.prefix}\033[0m")
                            vprint(7, '   \033[1;33m------------------------------------------------------\033[0m')
                            vprint(7)
                            #-----------------------#
                            res = checkAggregateCompatibility2UQ(PQ, UQ1, UQ2)
                            if not res['compatible']:
                                #-----------------------#
                                vprint(1, '\033[1;33m   ' + res['reason'])
                                vprint(1)
                                vprint(1, f"\033[1;31m   Privacy query {PQ.prefix} IS NOT COMPATIBLE with the utility policy !\033[0m")
                                #print(f"{PQ.prefix} is not compatible with the utility policy.",file=outputfile)
                                vprint(1)
                                #-----------------------#
                                comp = 'False'
                            else:
                                #-----------------------#
                                vprint(7, f"\033[1;32m   Privacy query {PQ.prefix} is compatible with utility queries {UQ1.prefix} and {UQ2.prefix}.\033[0m")
                                vprint(7)
                                #-----------------------#    
                    if comp == 'True':
                        #-----------------------#
                        vprint(1, f"\033[1;32m   Privacy query {PQ.prefix} is compatible with the utility policy.\033[0m")
                        vprint(1)
                        #-----------------------#


        # Prepare conclusion
        if comp == 'Maybe':
            compatibility = 'Maybe'
        elif comp == 'False':
            compatibility = 'False'

      
    # Conclusion
    vprint(1)
    vprint(1,'\033[1;34m===========\033[0m')
    vprint(1,'\033[1;34mConclusion:\033[0m')
    vprint(1,'\033[1;34m===========\033[0m')
    vprint(1)
    if compatibility == 'True':
        print('\033[1;32mPrivacy and utility Policies are compatible.\033[0m')
        print(f"No privacy risk detected!",file=outputfile)        
    elif compatibility == 'Maybe':
        print('\033[33mPrivacy and utility policies MAY NOT BE COMPATIBLE !\033[0m')        
    else:
        vprint(1,"\033[1;33mAt least one of privacy queries is incompatible with the utility policy !\033[0m")
        vprint(1)
        print('\033[1;31mPrivacy and utility policies ARE NOT COMPATIBLE !\033[0m')
        print(f"Privacy risks are detected!",file=outputfile)       
    print('+++++++++++++++++++++++++',file=outputfile)
        
    outputfile.close()
    suggestionsfile.close()
        

if __name__ == '__main__':
    main()
