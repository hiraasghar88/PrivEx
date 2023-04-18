#!/usr/bin/python3

import re
from datetime import datetime
import rdflib
from rdflib import Graph, Namespace, URIRef, BNode, Literal
import rdflib.namespace
from string import *

class TACQ(object):
    """
    Class for storing and manipulating TACQs.
    """

    # Attributes of a TACQ
    select = []     # list of output variables names
    aggregate = {}  # couple {function, variable}
    gp = []         # list of triplets {subject, predicate, object}
    filter = []     # list of initial filter conditions {opl, comp, opr}
    joins = []      # list of pairs of joining attributes (lists of couples of variables). Used for privacy query rewritting
    group_by = []   # list of grouping attributes
    size = 'inf'    # size of time windows (a string)
    step = 0        # step of time windows (a string)

    variables = {}  # dictionary of renamed variables {new : old}
    varTypes = {}   # dictionary of variable Types {var : type}
    prefix = "Q"    # prefix for variable names
    numVar = 1      # new variable number

    constatnts = {} # constants for freezing the graph pattern
    numConst = 1    # new constant number

    

    def __init__(self):
        self.select = []     
        self.aggregate = {}  
        self.gp = []         
        self.filter = []     
        self.joins = []      
        self.group_by = []  
        self.size = 'inf'   
        self.step = 0       

        self.variables = {}  
        self.varTypes = {}
        self.prefix = "Q"    
        self.numVar = 1

        self.constants = {}
        self.numConst = 1



    def copy(self):
        """
        Returns a copy of the query.

        inputs: - none
        output: - a TACQ
        """
        q = TACQ();
        q.select = self.select.copy()
        q.aggregate = self.aggregate.copy()
        for t in self.gp:
            q.gp.append(t.copy())
        for t in self.filter:
            q.filter.append(t.copy())
        for t in self.joins:
            q.joins.append(t)
        q.group_by = self.group_by.copy()
        q.size = self.size
        q.step = self.step

        q.variables = self.variables.copy()
        q.varTypes = self.varTypes.copy()
        q.prefix = self.prefix
        q.numVar = self.numVar

        q.constants = self.constants.copy()
        q.numConst = self.numConst

        return q
        


    def parse(self, query):
        """
        Parse a query expression (string) to fill the object.

        inputs: - query as a string
        output: - None
        """
        if not isinstance(query, str):
            raise TypeError('The parameter of parse() must be a string !')
        
        select = []
        aggregate = {}
        gp = []
        filter = []
        joins = []
        group_by = []
        size = 'inf'
        step = 0

        #
        # separate sub-parts of the query:
        #
        
        timewindowPart = groupPart = filterPart = wherePart = selectPart = ""

        
        #  TIMEWINDOW
        pos = query.find('TIMEWINDOW')
        if pos >= 0:
            timewindowPart = query[pos:]
            query = query[:pos]
            
        #  GROUP
        pos = query.find('GROUP')
        if pos >= 0:
            groupPart = query[pos:]
            query = query[:pos]
            
        #  FILTER
        pos = query.find('FILTER')
        if pos >= 0:
            filterPart = query[pos:]
            query = query[:pos]
            
        #  WHERE
        pos = query.find('WHERE')
        if pos >= 0:
            wherePart = query[pos:]
            query = query[:pos]
        else:
            raise TACQError('WHERE clause is mandatory !')
        
        #  SELECT
        pos = query.find('SELECT')
        if pos >= 0:
            selectPart = query[pos:]
        else:
            raise TACQError('The SELECT clause is madatory !')
        
        #
        # parse each part of the query
        #

        #  SELECT
        select = selectPart[6:].split()
        # check for aggregate funtion
        for s in select.copy():
            # if not a variable => supposed to be aggregate
            if s[0] != '?':
                # check query consistency
                if self.aggregate:
                    raise TACQError(f"Only one aggregate function is allowed [{s}] !")
                # transfer expression from select to aggregate
                select.remove(s)
                tmp = msplit('()\n ', s)
                aggregate['function'] = tmp[0]
                aggregate['variable'] = tmp[1]
                if tmp[1][0] != '?':
                    raise TACQError(f"Aggregates must be computed over a variable [{tmp[0]}({tmp[1]})] !")

        #  WHERE => GP
        tmp  = msplit('{}.', wherePart[5:])
        for i in tmp:
            t = msplit('(), \n', i)
            if len(t) == 3:
                tripple = {'subject' : t[0], 'predicate' : t[1], 'object' : t[2], 'timestamp' : 'any'}
            elif len(t) == 4:
                tripple = {'subject' : t[0], 'predicate' : t[1], 'object' : t[2], 'timestamp' : t[3]}
            gp.append(tripple)
        # check query consistency
        for s in select:
            OK = False
            for p in gp:
                if  s in [p['subject'], p['object'], p['timestamp']] or s == '?timeWindowEnd':
                    OK = True
            if not OK:
                raise TACQError(f"Output variable {s} must appear in the graph pattern !")
        if aggregate:
            OK = False
            var = aggregate['variable']
            for p in gp:
                if var in [p['subject'], p['object'], p['timestamp']]:
                    OK = True
            if not OK:
                raise TACQError(f"Aggregate variable {var} must appear in the graph pattern !")

        #  FILTER
        if filterPart:
            b = filterPart.find('(')
            e = filterPart.find(')')
            filters = msplit('&}', filterPart[b+1:e])
            for f in filters:
                tmp = f.split()
                # type left operand (date -> int -> float -> string)
                try:
                    opl = datetime.fromisoformat(tmp[0])
                except ValueError:
                    try:
                        opl = int(tmp[0])
                    except ValueError:
                        try:
                            opl = float(tmp[0])
                        except ValueError:
                            opl = str(tmp[0])
                # type left operand (date -> int -> fload -> string)
                try:
                    opr = datetime.fromisoformat(tmp[2])
                except ValueError:
                    try:
                        opr = int(tmp[2])
                    except ValueError:
                        try:
                            opr = float(tmp[2])
                        except ValueError:
                            opr = str(tmp[2])
                filter.append({'opl' : opl, 'comp' : tmp[1], 'opr' : opr})

        #  GROUP BY
        if groupPart:
            group_by = groupPart[8:].split()
            # check query consistency
            for s in select:
                if not s in group_by:
                    raise TACQError(f"Output variable {s} have to be in the GROUP BY expression !")
            for g in group_by:
                OK = False
                for p in gp:
                    if g in [p['subject'], p['object'], p['timestamp']] or g == '?timeWindowEnd':
                        OK = True
                if not OK:
                    raise TACQError(f"Group variable {g} must appear in the graph pettern !")

            if aggregate and aggregate['variable'] in group_by:
                raise TACQError(f"Aggregate variable {var} must not appear in the group definition !")


        #  TIME WINDOW
        if timewindowPart:
            b = timewindowPart.find('(')
            e = timewindowPart.find(')')
            tw = msplit(' ,\n', timewindowPart[b+1:e])
            for i in ascii_letters:
                tw[0] = tw[0].replace(i, '')
                tw[1] = tw[1].replace(i,'')
            size=tw[0]
            step=tw[1]
                     

        self.select = select
        self.aggregate = aggregate
        self.gp = gp
        self.filter = filter
        self.group_by = group_by                
        self.size= size                
        self.step = step        
        self.variables = {}
        self.varTypes = {}
        self.prefix = "Q"
        self.numVar = 1
        self.constants = {}
        self.numConst = 1



    def addVar(self, output=False, old=None):
        """
        Create a new varaible.

        inputs: - output -> if true, create an output variable '?o...'
                - old -> corresponding old variable name
        output: - new variable name
        """
        if not isinstance(output, bool):
            raise TypeError('The parameter "output" of addVar() must be a booelan !')
        if not isinstance(old, str):
            raise TypeError('The parameter "old" of addVar() must be a string !')
        
        # mark output variables
        if output:
            new = '?o_' + self.prefix + '_' 
        else:
            new = '?v_' + self.prefix + '_' 
        # create the new variable
        new = new + str(self.numVar)
        self.numVar = self.numVar + 1
        self.variables[new] = old
        self.varTypes[new] = 'unknown'
        return new



    def reify(self):
        """
        Perform reification of the graph pattern.

        inputs: - none
        output: - none
        """

        gp = []
        numR = 1

        # for each triple in GP
        for t in self.gp:
            v = '?r_' + self.prefix + '_' + str(numR)
            numR = numR + 1
            gp.append({'subject' : v, 'predicate' : ':subject', 'object' : t['subject'], 'timestamp' : 'any'})
            gp.append({'subject' : v, 'predicate' : ':predicate', 'object' : t['predicate'], 'timestamp' : 'any'})
            gp.append({'subject' : v, 'predicate' : ':object', 'object' : t['object'], 'timestamp' : 'any'})
            if t['timestamp'] != 'any':
                gp.append({'subject' : v, 'predicate' : ':timestamp', 'object' : t['timestamp'], 'timestamp' : 'any'})

        self.gp = gp



    def renameVariables(self, prefix='Q'):
        """
        Renames all the variables in the query.

        inputs: - prefix -> prefix for new variable names. Default  is "Q"
        output: - None
        """
        if not isinstance(prefix, str):
            raise TypeError('The parameter "prefix" of renameVariable() must be a string !')
        
        self.prefix = prefix
        self.variables = {}
        self.varTypes  = {}

        sel = []
        agg = {}
        gp = []
        filters = []
        joins = []
        group = []

        # SELECT
        for s in self.select:
            new = self.addVar(output=True, old=s)
            sel.append(new)
        
        # AGGREGATE
        if self.aggregate:
            new = self.addVar(old=self.aggregate['variable'])
            agg['function'] = self.aggregate['function']
            agg['variable'] = new
        
        # WHERE
        for t in self.gp:
            tripple = {}
            # subject is a variable
            if t['subject'][0] == '?' and t['subject'][1] != 'r':
                # unknown ?
                new = [n for (n, o) in self.variables.items() if o == t['subject']]
                if not new:
                    new = self.addVar(old=t['subject'])
                else:
                    new = new[0]
                tripple['subject'] = new
            # subject not a variable => add FILTER
            else:
                new = self.addVar(output=True, old='Literal')
                self.filter.append({'opl' : new, 'comp' : ' = ', 'opr' : t['subject']})
                tripple['subject'] = new
                
            # predicate
            tripple['predicate'] = t['predicate']
            
            # object is a variable
            if t['object'][0] == '?':
                # unknown ?
                new = [n for (n, o) in self.variables.items() if o == t['object']]
                if not new:
                    new = self.addVar(old=t['object'])
                else:
                    new = new[0]
                tripple['object'] = new
            # object not a variable => add FILTER
            else:
                new = self.addVar(output=True, old='Literal')
                filters.append({'opl' : new, 'comp' : ' = ', 'opr' : t['object']})
                tripple['object'] = new

            # timestamp is a variable
            if t['timestamp'][0] == '?':
                # unknown ?
                new = [n for (n, o) in self.variables.items() if o == t['timestamp']]
                if not new:
                    new = self.addVar(output=True, old=t['timestamp'])
                else:
                    new = new[0]
                tripple['timestamp'] = new
            # timestamp is not a variable => add FILTER if not 'any'
            elif str(t['timestamp']) != 'any':
                new = self.addVar(output=True, old='Literal')
                filters.append({'opl' : new, 'comp' : ' = ', 'opr' : t['timestamp']})
                tripple['timestamp'] = new
            else:
                tripple['timestamp'] = 'any'

            gp.append(tripple)

        # FILTER
        for f in self.filter:
            filt = {}
            # opl is a variable
            if isinstance(f['opl'], str) and f['opl'][0] == '?':
                new = [n for (n, o) in self.variables.items() if o == f['opl']]
                filt['opl'] = new[0]
            #or not
            else:
                filt['opl'] = f['opl']

            # comp
            filt['comp'] = f['comp']
                
            #opr is a variable
            if isinstance(f['opr'], str) and f['opr'][0] == '?':
                new = [n for (n, o) in self.variables.items() if o == f['opr']]
                filt['opr'] = new[0]
            #or not
            else:
                filt['opr'] = f['opr']
            filters.append(filt)

        # JOINS
        for join in range(len(self.joins)):
            (i, j) = self.joins[join]
            ni = [n for (n,o) in self.variables.items() if o == i]
            nj = [n for (n,o) in self.variables.items() if o == j]
            joins.append((ni[0], nj[0]))
            
        # GROUP
        for g in self.group_by:
            new = [n for (n, o) in self.variables.items() if o == g]
            group.append(new[0])

        # updates query
        self.select = sel
        self.aggregate = agg
        self.gp = gp
        self.filter = filters
        self.joins = joins
        self.group_by = group
        
    def extractJoins(self):
        """
        Extracts joins from graph pattern.

        inputs: - None
        output: - None
        """
        Vars = []
        for p in self.gp:
            # subject is a variable
            if p['subject'][0] == '?' and p['subject'][1] != 'r':
                # unknown variable
                if not p['subject'] in Vars:
                    Vars.append(p['subject'])
                # known variable
                else:
                    # create a new variable 
                    new = self.addVar(old=self.variables[p['subject']])
                    # add a join condition
                    self.joins.append((p['subject'], new))
                    # replace the variable
                    p['subject'] = new
                    
            # object is a variable
            if p['object'][0] == '?':
                # unknown variable
                if not p['object'] in Vars:
                    Vars.append(p['object'])
                # known variable
                else:
                    # create a new variable 
                    new = self.addVar(old=self.variables[p['object']])
                    # add a join condition
                    self.joins.append((p['object'], new))
                    # replace the variable
                    p['object'] = new



    def typeVars(self):
        """
        Try to determine the type of the variables, starting from filters and joins.
        This method must be called only after variable renaming, because constants are extracted from GP while renaming.

        inputs: - None
        output: - None 
        """
        # Start with ?timeWindowEnd
        for (n, o) in self.variables.items():
            if str(o) == '?timeWindowEnd':
                self.varTypes[n] = datetime

        # Next with timestamps
        for t in self.gp:
            if t['timestamp'][0] == '?':
                self.varTypes[t['timestamp']] = datetime


        # Next with filter terms comprising constants
        for c in self.filter:
            opl = c['opl']
            opr = c['opr']
           # left operand is a variable
            if type(opl) == str and opl[0] == '?':
                # right operand is not a string => opl has same type as opl
                if type(opr) != str:
                    self.varTypes[opl] = type(opr)
                # opr is a string => opl has same type as opr too
                elif opr[0] != '?':
                    self.varTypes[opl] = type(opr)
                # opr is a variable => opl and opr have the same type
                else:
                    if self.varTypes[opl] == 'unknown':
                        self.varTypes[opl] = self.varTypes[opr]
                    else:
                        self.varTypes[opr] = self.varTypes[opl]
            # left operand is not a variable
            else:
                # right operand is a variable => same type as opl
                if type(opr) == str and opr[0] == '?':
                    self.vraTypes[opr] = type(opl)
                # type mismatch
                else:
                    raise TypeError(f"Incompatible types in filter ({opl} {c['comp']} {opr})")
        # Continue with joins to propagate types
        for (i,j) in self.joins:
            try:
                if self.varTypes[j] != 'unknown':
                    self.varTypes[i] = self.varTypes[j]
                if self.varTypes[i] != 'unknown':
                    self.varTypes[j] = self.varTypes[i]
            except KeyError:
                self.varTypes[j] = self.varTypes[i] = 'unknown'
        

    def listGPVars(self, timestamps = True):
        """
        Build a string listing all variables present in the graph pattern.
        Used for Theorem 4.1

        inputs: - None
        outpur: - a string
        """
        vars = []
        for t in self.gp:
            # subject
            if t['subject'][0] == '?' and t['subject'][1] != 'r' and not t['subject'] in vars:
                vars.append(t['subject'])
            # object
            if t['object'][0] == '?' and not t['object'] in vars:
                vars.append(t['object'])
            # timestamp
            if timestamps and t['timestamp'] != 'any' and t['timestamp'][0] == '?'and not t['timestamp'] in vars:
                vars.append(t['timestamp'])

        # build the result
        res = ''
        for v in vars:
            res = res + str(v) + ' '

        return res[:-1]



    def union(self, query):
        """
        Computes the union of conjunctive part of the local TACQ and the one of a given query.

        inputs: - query -> another TACQ
        output: - a new TACQ containing the union of sleect, graph patterns, filter, joins and variable definitions
        """
        if not isinstance(query, TACQ):
            raise TypeError('The parameter "query" of union() must be a TACQ !')
        
        # create a new TACQ as a copy of self
        res = TACQ()

        # do the union
        res.select = self.select.copy() + query.select.copy()
        res.gp = self.gp.copy() + query.gp.copy()
        res.joins = self.joins.copy() + query.joins.copy()
        res.filter = self.filter.copy() + query.filter.copy()
        res.variables = self.variables.copy()
        res.variables.update(query.variables.copy())
        res.constants = self.constants.copy()
        res.constants.update(query.constants.copy())
        res.varTypes = self.varTypes.copy()
        res.varTypes.update(query.varTypes.copy())

        return res


    def addConst(self, var=""):
        """
        Create a new constant for freezing a given variable.

        inputs: - var -> variable name
        output: - new constant name
        """
        if not isinstance(var, str):
            raise TypeError('The parameter "var" of addConst() must be a string !')
        
        # mark output variables
        if var[1] == 'o':
            new = 'oc'
        else:
            new = 'c'
        # create the new variable
        new = new + str(self.numConst)
        self.numConst = self.numConst + 1
        self.constants[var] = new
        return new
        

    def freeze(self):
        """
        Freezes the graph pattern of the query, one constant per variable.

        inputs: - None
        output: - RDFlib Graph
        """
        graph = Graph()
        ns = Namespace('http://example.org/')

        # for each tripplet in GP
        for t in self.gp:
            tripplet = {}
            # subject
            var = t['subject']
            if var[0] == '?':
                if var in self.constants.keys():
                    tripplet['subject'] = self.constants[var]
                else:
                    tripplet['subject'] = self.addConst(var)
            else:
                tripplet['subject'] = var

            # predicate
            tripplet['predicate'] = t['predicate']

            # object
            var = t['object']
            if var[0] == '?':
                if var in self.constants.keys():
                    tripplet['object'] = self.constants[var]
                else:
                    tripplet['object'] = self.addConst(var)
            else:
                tripplet['object'] = var

         
            graph.add((Literal(tripplet['subject']), ns[tripplet['predicate']], Literal(tripplet['object'])))
            
        return graph
    


    def printVariables(self):
        """
        Prints the correspondance between new variables and old ones after renaming.

        inputs: - None
        output: - None
        """
        if self.variables:
            # max size of new variable names
            n = [len(k) for k in self.variables.keys()]
            Mn = max(n + [3])
            # max size of old variable names
            o = [len(v) for v in self.variables.values()]
            Mo = max(o + [3])
            # header
            print(f"+-{'-' * Mn}-+-{'-' * Mo}-+")
            print(f"| {'New':{Mn}} | {'Old':{Mo}} |")
            print(f"+-{'-' * Mn}-+-{'-' * Mo}-+")
            # variables
            for v in self.variables.keys():
                if self.variables[v]:
                    print(f"| {v:{Mn}} | {self.variables[v]:{Mo}} |")
            # footer
            print(f"+-{'-' * Mn}-+-{'-' * Mo}-+")



    def printVarTypes(self):
        """
        Prints variables and their types.

        inputs: - None
        output: - None
        """
        if self.varTypes:
            # max size of variable names
            n = [len(str(k)) for k in self.varTypes.keys()]
            Mn = max(n + [3])
            # max size of variable types
            t = [len(str(v)) for v in self.varTypes.values()]
            Mt = max(t +[4])
           # header
            print(f"+-{'-' * Mn}-+-{'-' * Mt}-+")
            print(f"| {'Var':{Mn}} | {'Type':{Mt}} |")
            print(f"+-{'-' * Mn}-+-{'-' * Mt}-+")
            # variable names
            for v in self.varTypes.keys():
                if self.varTypes[v]:
                    print(f"| {v:{Mn}} | {str(self.varTypes[v]):{Mt}} |")
            # footer
            print(f"+-{'-' * Mn}-+-{'-' * Mt}-+")



    def printConstants(self):
        """
        Prints the correspondace between constants and variables after freezing.

        inputs: - None
        output: - None
        """
        if self.constants:
            # max size of variable names
            lv = [len(k) for k in self.constants.keys()]
            Mv = max(lv + [3])
            # max size of constant names
            lc = [len(v) for v in self.constants.values()]
            Mc = max(lc + [5])
            # header
            print(f"+-{'-' * Mv}-+-{'-' * Mc}-+")
            print(f"| {'Var':{Mv}} | {'Const':{Mc}} |")
            print(f"+-{'-' * Mv}-+-{'-' * Mc}-+")
            # varaibles
            for c in self.constants.keys():
                print(f"| {c:{Mv}} | {self.constants[c]:{Mc}} |")
            # footer
            print(f"+-{'-' * Mv}-+-{'-' * Mc}-+")



    def isConjunctive(self):
        """
        Test if the query is a conjunctive one.

        inputs: - None
        output: - boolean value
        """
        return not self.aggregate and not self.filter and not self.group_by and self.size == 'inf' and self.step == 0
        
    

    def toString(self, show='sawfjgt'):
        """
        Converts the TACQ into a string.
    
        inputs: - show -> indicates what is shown (s -> select, a->aggregate, w->gp, n -> gp without timestamps, f->filter, j-> joins, g->group by, t->time window)
        output: - expression of the query
        """
        if not isinstance(show, str):
            raise TypeError('The parameter "show" of toString() must be a string !')
        
        res = ''
        # output variables
        if 's' in show:
            res = 'SELECT '
            for i in self.select:
               res = res + str(i) + ' '
            res = res[:-1]
            
        # aggregate
        if 'a' in show and self.aggregate:
            res = res + ' ' + self.aggregate['function'] + '(' + self.aggregate['variable'] + ')\n'
        elif 's' in show:
            res = res + '\n'
            
        #graph pattern
        if 'w' in show or 'n' in show:
            res = res + 'WHERE { '
            for i in self.gp:
                if str(i['timestamp']) != 'any' and not 'n' in show:
                    res = res + '(' + str(i['subject']) + ' ' + str(i['predicate']) + ' ' + str(i['object']) +', ' + str(i['timestamp']) + ') . '
                else:
                     res = res + str(i['subject']) + ' ' + str(i['predicate']) + ' ' + str(i['object']) + ' . '
                
        # filter conditions
        if ('f' in show and self.filter) or ('j' in show and self.joins):
            res = res + '\nFILTER( '
            # filters first
            if 'f' in show:
                for i in self.filter:
                    try:
                        res = res + str(i['opl']) + ' ' + str(i['comp']) + ' ' + i['opr'].isoformat() + ' && '
                    except:
                        res = res + str(i['opl']) + ' ' + str(i['comp']) + ' ' + str(i['opr']) + ' && '
            if 'j' in show:
                for (i, j) in self.joins:
                    res = res + str(i) + ' = ' + str(j) + ' && '
            res = res[:-4] + ' )'
        else:
            res = res[:-3]
        res = res + ' }'
        
        # group by
        if 'g' in show and self.group_by:
            res = res + '\nGROUP BY '
            for i in self.group_by:
                res = res + str(i) + ' '
            res = res[:-1]
            
        # time windows
        if 't' in show and (self.size != 'inf' or self.step !=0):
            res = res + '\nTIMEWINDOW (' + str(self.size) + ', ' + str(self.step) + ')'
            
        # result
        return res



def msplit(delimiters, string, maxsplit=0):
    """
    A simple function to split a string with different delimiters.

    inputs: - delimiters  -> string containing all delimiters
            - string      -> string to split
            - maxspllit   -> max number of extracted sub-strings (0 = no limit)
    output: - list of substrings
    """
    if not isinstance(delimiters, str):
        raise TypeError('The parameter "delimiters" of msplit() must be a string !')
    if not isinstance(string, str):
       raise TypeError('The parameter "string" of msplit() must be a string !')
    if not isinstance(maxsplit, int):
        raise TypeError('The parameter "maxsplit" of msplit() must be an integer !')
        
    regexPattern = '|'.join(map(re.escape, delimiters))
    res = re.split(regexPattern, string, maxsplit)
    for s in range(len(res)):
        res[s] = res[s].strip()
    while('' in res) :
        res.remove('')  
    return res



class TACQError(Exception):
    """
    Exception class for errors in TACQ expression, mostly consistency in the use of variables.
    """
    pass



# some simple tests
if __name__ == '__main__':
    print('----------------')
    print('Test of parse():')
    print('----------------')
    query = TACQ()
    query.parse("""
        PREFIX ns:<http://example.com>
        
        SELECT ?a ?timeWindowEnd 
        max(?c)
        WHERE {?a ns:p

        ?b.
        ?b ns:q ?c . ?b ns:r "toto" .FILTER(?a > 2
        .
        ?a < ?b . ?b > 12 }
        GROUP BY ?a ?timeWindowEnd
        ?b TIMEWINDOW (2h,
        1h)
        """)
    print('select:   ', query.select)
    print('aggregate:', query.aggregate)
    print('gp:      ', query.gp)
    print('filter:   ', query.filter)
    print('joins:    ', query.joins)
    print('group_by: ', query.group_by)
    print('size:     ', query.size)
    print('step:     ', query.step)
    print()

    # toString
    print('-------------------')
    print('Test of toString():')
    print('-------------------')
    print('Full query: toString()')
    print(query.toString(), '\n')
    print('Cojunctive part: toString("sw")')
    print(query.toString('sw'), '\n')
    print('With filter: toString("swf")')
    print(query.toString('swf'), '\n')
    print('With group: toString("swfg")')
    print(query.toString('swfg'), '\n')
    print('with aggregate: toString("sawfg")')
    print(query.toString('sawfg'), '\n')
    print('With time window: toString("sawfgt")')
    print(query.toString('sawfgt'), '\n')

    # renameVariables
    print('--------------------------')
    print('Test of renameVariables():')
    print('--------------------------')
    query.renameVariables()
    print(query.toString(), '\n')

    # printVariables
    print('-------------------------')
    print('Test of printVariables():')
    print('-------------------------')
    query.printVariables()
    print()

    # reify
    print('----------------')
    print('Test de reify():')
    print('----------------')
    query.reify()
    print(query.toString())
    print()

    # extractJoins
    print('-----------------------')
    print('Test de extractJoins():')
    print('-----------------------')
    query.extractJoins()
    print(query.toString(), '\n')
    query.printVariables()
    print()

    # typeVars and printVarTypes
    print('-------------------')
    print('Test de typeVars():')
    print('-------------------')
    query.typeVars()
    print('Variable types:')
    query.printVarTypes()
 

    # union
    print('----------------')
    print('Test of union():')
    print('----------------')
    q1 = TACQ()
    q1.parse('SELECT ?a ?b ?d WHERE { (?a ns:ppp ?b, ?d) . FILTER(?b > 3)}')
    q1.renameVariables('q1')
    print('q1:')
    print(q1.toString())
    q1.printVariables()
    print()

    q2 = TACQ()
    q2.parse('SELECT ?a ?c WHERE { ?a ns:qqq ?b . ?b ns:rrr ?c . FILTER(?a < 2}')
    q2.renameVariables('q2')
    q2.extractJoins()
    print('q2:')
    print(q2.toString())
    q2.printVariables()
    print()

    q3 = q1.union(q2)
    print('Union of q1 and q2:')
    print(q3.toString())
    q3.printVariables()
    print()

    # freeze
    print('-----------------')
    print('Test of freeze():')
    print('-----------------')
    freezing = query.freeze()
    print(freezing.serialize(format="turtle"))
    query.printConstants()
   
    
