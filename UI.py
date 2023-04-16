#!/usr/bin/python3
# coding: utf-8

# This will import all the widgets
# and modules which are available in
# tkinter and ttk module
from tkinter import *
from tkinter import ttk
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from rdflib import Graph,Namespace,URIRef
from PIL import Image, ImageTk, ImageDraw, ImageFont
from tkinter import messagebox
from tkinter import filedialog
import compatibilityChecking
import os
import re
import sys



def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
 
# creates a Tk() object
master = Tk()
 
# sets the geometry of main master window
width= master.winfo_screenwidth()               
height= master.winfo_screenheight()               
master.geometry("%dx%d" % (width, height))
master.title("Detecting and explaining privacy risks")

m_frame= Frame(master)
m_frame.pack(fill=BOTH, expand=1)

m_canvas= Canvas(m_frame)

second_frame=Frame(m_canvas)
m_canvas.create_window((0,0), window=second_frame, anchor="nw")

mx_scrollbar = ttk.Scrollbar(m_frame, orient=HORIZONTAL, command=m_canvas.xview)

m_scrollbar = ttk.Scrollbar(m_frame, orient=VERTICAL, command=m_canvas.yview)
mx_scrollbar.pack(side=BOTTOM, fill=X)

m_canvas.pack(side=LEFT, fill=BOTH, expand=1)
m_scrollbar.pack(side=RIGHT, fill=Y)


m_canvas.configure(xscrollcommand=mx_scrollbar.set, yscrollcommand=m_scrollbar.set)
m_canvas.bind('<Configure>', lambda e:m_canvas.configure(scrollregion=m_canvas.bbox("all")))

#reading PQs in SPARQL
with open(resource_path('PQs.sparql'),"r") as file:
    global q
    q = ""
    for line in file:
        if line.startswith("SELECT"):
            q= q+(line[0:])
        if line.startswith("WHERE"):
                q= q+ ""+ (line[0:])
        if line.startswith("GROUP BY"):
            q= q+ ""+ (line[0:])
        if line.startswith("TIMEWINDOW"):
            q= q+ ""+ (line[0:])            
q=q.split('SELECT')
q=q[1:]
#reading PQs in text
global pqs
pqs=''
with open(resource_path('PQs.txt'),"r") as file:          
        for line in file:            
            if line=='\n':
               line.strip('\n')
            else:
                pqs=pqs+(line[0:])               
pqs=pqs.split('\n')
pqs=pqs[:-1]

#creating treeview to display PQs
style = ttk.Style()
style.theme_use("default")

style.configure('Treeview', background='white',foreground='black', fieldbackground='white', rowheight=132)
style.map('Treeview',background=[('selected','darkgrey')])

tree_frame= Frame(m_canvas,highlightbackground="darkgrey", highlightthickness=2)
m_canvas.create_window((50,5), window=tree_frame, anchor="nw")

treeB_frame= Frame(m_canvas)
m_canvas.create_window((50,317), window=treeB_frame, anchor="nw")


treey_scroll=Scrollbar(tree_frame,orient='vertical')
treey_scroll.pack(side=RIGHT, fill=Y)

treex_scroll=Scrollbar(tree_frame,orient='horizontal')
treex_scroll.pack(side=BOTTOM, fill=X)


tv = ttk.Treeview(tree_frame,height=2,selectmode='none', yscrollcommand=treey_scroll.set,xscrollcommand=treex_scroll.set)
tv.pack(expand=YES, fill=BOTH)

treey_scroll.config(command=tv.yview)
treex_scroll.config(command=tv.xview)

tv["columns"] = ("1")

tv.column("#0",width=100, minwidth=110, anchor=CENTER)
tv.column("1", width=753, minwidth=1200)


tv.heading("#0", text='Query ID')
tv.heading("1", text='Specification of your sensitive data: No answer to following privacy queries should be deduced',anchor='nw')

tv.tag_configure('oddrow',background='lightcyan')
tv.tag_configure('evenrow',background='lightblue')

#inserting PQs in treeview

for i,j in enumerate(pqs):
    if i%2==0:
            tv.insert(parent='', index='end', iid='12'+str(i), text=('PQ'+str(i+1)), values=([pqs[i]]), tags=('evenrow',))
            for m,n in enumerate(q):
                if m==i:
                        tv.insert(parent='12'+str(i), index='end', iid='112'+str(m),text='', values=(['SELECT'+q[i]]))
    else:
        tv.insert(parent='', index='end', iid='12'+str(i), text=('PQ'+str(i+1)), values=([pqs[i]]), tags=('oddrow',))
        for m,n in enumerate(q):
            if m==i:
                 tv.insert(parent='12'+str(i), index='end', iid='112'+str(m),text='', values=(['SELECT'+q[i]]))  

#reading UQs in SPARQL
with open(resource_path('UQs.sparql'),"r") as fileUQ:
    global UQ
    UQ = ""
    for line in fileUQ:
        if line.startswith("SELECT"):
            UQ= UQ+(line[0:])
        if line.startswith("WHERE"):
                UQ= UQ+ ""+ (line[0:])
        if line.startswith("GROUP BY"):
            UQ= UQ+ ""+ (line[0:])
        if line.startswith("TIMEWINDOW"):
            UQ= UQ+ ""+ (line[0:])            
UQ=UQ.split('SELECT')
UQ=UQ[1:]

#reading UQs in text
with open(resource_path('UQs.txt'),"r") as file:
    
    uqs = ""
    sp=""
    lp=""
    for i,j in enumerate(file):
        if i>0 and j.startswith("I"):
            uqs= uqs+(j[0:])
        if i>0 and j.startswith("UQ"):
            lp= lp+(j[0:])
        if i==0:
           sp= sp+(j[0:])           
uqs=uqs.split('\n')
lp=lp.split('\n')

#Creating treeview to display UQs
tree2_frame= Frame(m_canvas,highlightbackground="darkgrey", highlightthickness=2)
m_canvas.create_window((990,5), window=tree2_frame, anchor="nw")

tree2_scroll=Scrollbar(tree2_frame,orient='vertical')
tree2_scroll.pack(side=RIGHT, fill=Y)

tree2x_scroll=Scrollbar(tree2_frame,orient='horizontal')
tree2x_scroll.pack(side=BOTTOM, fill=X)


tview = ttk.Treeview(tree2_frame,height=2,selectmode='none',yscrollcommand=tree2_scroll.set,xscrollcommand=tree2x_scroll.set)
tview.pack(expand=YES, fill=BOTH)

tree2_scroll.config(command=tview.yview)
tree2x_scroll.config(command=tview.xview)
tview["columns"] = ("1")

tview.column("#0",width=100, minwidth=110, anchor=CENTER)
tview.column("1", width=753, minwidth=1200)

tview.heading("#0", text='Query ID')
tview.heading("1", text='Utility queries expressed by the energy provider to specify the data he needs for further data analytics and recommendation purposes',anchor='nw')


tview.tag_configure('odd',background='lightcyan')
tview.tag_configure('even',background='lightblue')

#inserting UQs in treeview

for i,j in enumerate(uqs):
    for e,f in enumerate(lp):
        if i%2==0:
            if i==e:
                tview.insert(parent='', index='end', iid='123'+str(i), text=(f), values=([uqs[i]]), tags=('even',))
                for m,n in enumerate(UQ):
                    if m==i:
                        tview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+UQ[i]]))
        else:
            if i==e:
                tview.insert(parent='', index='end', iid='123'+str(i), text=(f), values=([uqs[i]]), tags=('odd',))
                for m,n in enumerate(UQ):              
                    if m==i:
                        tview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+UQ[i]])) 


#Creating treeview to show privacy risk explanations
third_frame= Frame(m_canvas,highlightbackground="darkgrey", highlightthickness=2)
m_canvas.create_window((50,360), window=third_frame, anchor="nw")

thirdB_frame= Frame(m_canvas)
m_canvas.create_window((50,937), window=thirdB_frame, anchor="nw")

thirdS_frame= Frame(m_canvas)
m_canvas.create_window((1400,550), window=thirdS_frame, anchor="nw")

thirdS1_frame= Frame(m_canvas)
m_canvas.create_window((1400,625), window=thirdS1_frame, anchor="nw")


treeviewy_scroll=Scrollbar(third_frame,orient='vertical')
treeviewy_scroll.pack(side=RIGHT, fill=Y)

treeviewx_scroll=Scrollbar(third_frame,orient='horizontal')
treeviewx_scroll.pack(side=BOTTOM, fill=X)


treev = ttk.Treeview(third_frame,height=4,selectmode='none',yscrollcommand=treeviewy_scroll.set,xscrollcommand=treeviewx_scroll.set)
treev.pack(expand=YES, fill=BOTH)

treeviewy_scroll.config(command=treev.yview)
treeviewx_scroll.config(command=treev.xview)

treev["columns"] = ("1")

treev.column("#0",width=70, minwidth=100, anchor=CENTER)
treev.column("1", width=1200, minwidth=3000)


treev.heading("#0", text='')
treev.heading("1", text='Privacy Risks Analysis',anchor='nw')

#Code for removing all the queries from the list that raise privacy risk 
def Removequeries():

    with open(resource_path('suggestions.txt'),"r") as file:
        
        UQsugg = ""
        
        for line in file:
            
            if line.startswith("Remove"):
                UQsugg= UQsugg+ ""+ (line[0:])
            if line.startswith("Generalize"):
                UQsugg= UQsugg+ ""+ (line[0:])
            if line.startswith("Replace the aggregate"):
                UQsugg= UQsugg+ ""+ (line[0:])
            if line.startswith("Modify"):
                UQsugg= UQsugg+ ""+ (line[0:])
            if line.startswith(">"):
                UQsugg= UQsugg+ ""+ (line[0:])        
        UQNum = re.findall(r'\d+', UQsugg)
        UQNum=sorted(set(UQNum))
        
    for widget in thirdS_frame.winfo_children():
                widget.destroy()
                
    for widget in thirdS1_frame.winfo_children():
                widget.destroy()

    for item in treev.get_children():
              treev.delete(item)

    for s,t in enumerate(UQNum):        
        for x,y in enumerate(lp):
            y=y.replace('UQ','')
            print(y)
            if t==y:                
                for m,n in enumerate(UQ):            
                    if m==x:                        
                        with open(resource_path('UQs.sparql'),"r+") as f:
                                                data=f.read()
                                                v1=""
                                                n= 'SELECT' +n                                                
                                                p1=(n).replace("?",r"\?")
                                                p1=p1.replace("(",r"\(")
                                                p1=p1.replace(")",r"\)")                                                
                                                data = re.sub(p1,v1, data)
                                                datq=data.replace('\\','')
                                                f.seek(0)
                                                f.truncate()
                                                f.write(data)
                for p,q in enumerate(uqs):
                    if p==x:
                        with open(resource_path('UQs.txt'),"r+") as f:
                                        data=f.read()
                                        vv='UQ'+str(t)
                                        v1=""
                                        p1= (q).replace("?",r"\?")
                                        data = re.sub(p1, v1, data)
                                        data = re.sub(vv, v1, data)
                                        f.seek(0)
                                        f.truncate()
                                        f.write(data)

                       
                                                        
                with open(resource_path('UQs.sparql'),"r") as fileUQ:
                                                        
                                                        R_UQ = ""
                                                        for line in fileUQ:
                                                            if line.startswith("SELECT"):
                                                                R_UQ= R_UQ+(line[0:])
                                                            if line.startswith("WHERE"):
                                                                R_UQ= R_UQ+ ""+ (line[0:])
                                                            if line.startswith("GROUP BY"):
                                                                RUQ= R_UQ+ ""+ (line[0:])
                                                            if line.startswith("TIMEWINDOW"):
                                                                R_UQ= R_UQ+ ""+ (line[0:])            
                R_UQ=R_UQ.split('SELECT')
                R_UQ=R_UQ[1:]

                #reading UQs in text
                with open(resource_path('UQs.txt'),"r") as file:
                                                        
                                                        r_uq = ""
                                                        r_sp=""
                                                        llp=""
                                                        for i,j in enumerate(file):
                                                            if i>0 and j.startswith("I"):
                                                                r_uq= r_uq+(j[0:])
                                                            if i>0 and j.startswith("UQ"):
                                                                llp= llp+(j[0:])
                                                            if i==0:
                                                                r_sp= r_sp+(j[0:])           
                r_uq=r_uq.split('\n')
                llp=llp.split('\n')

                for item in tview.get_children():
                                                        tview.delete(item)
                            
                for i,j in enumerate(r_uq):
                    for e,f in enumerate(llp):
                                                    if i%2==0:
                                                        if i==e:
                                                            tview.insert(parent='', index='end', iid='123'+str(i), text=(f), values=([r_uq[i]]), tags=('even',))
                                                            for m,n in enumerate(R_UQ):                                    
                                                                if m==i:
                                                                    tview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+R_UQ[i]]))
                                                    else:
                                                        if i==e:
                                                            tview.insert(parent='', index='end', iid='123'+str(i), text=(f), values=([r_uq[i]]), tags=('odd',))
                                                            for m,n in enumerate(R_UQ):              
                                                                if m==i:
                                                                    tview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+R_UQ[i]]))    

    tk.messagebox.showinfo("", "The utility queries involved in privacy risks are removed from the list of utility queries.")         

#defining window for the negotaition
def OpenWindow():
    # Toplevel object which will
    # be treated as a new window
    gui_window1 = Toplevel(master)
    #Create an instance of tkinter frame or window
    
   
    #Define the geometry of window
    gui_width= gui_window1.winfo_screenwidth()               
    gui_height= gui_window1.winfo_screenheight()               
    gui_window1.geometry("%dx%d" % (gui_width, gui_height))
      
    gui_window1.title("Negotiating the utility queries to reduce the privacy risks")

    main_frame1= Frame(gui_window1)
    main_frame1.pack(fill=BOTH, expand=1)

    
    m1_canvas= Canvas(main_frame1)

    second_frame1=Frame(m1_canvas)
    m1_canvas.create_window((0,5), window=second_frame1, anchor="nw")


    cbss = dict()

    query1_frame=Frame(m1_canvas)
    m1_canvas.create_window((0,5), window=query1_frame, anchor="nw")   

    query_frame=Frame(m1_canvas)
    m1_canvas.create_window((0,35), window=query_frame, anchor="nw")

    query2_frame=Frame(m1_canvas)
    m1_canvas.create_window((1385,865), window=query2_frame, anchor="nw")

    m_scrollbar = ttk.Scrollbar(main_frame1, orient=VERTICAL, command=m1_canvas.yview)

    m1_canvas.pack(side=LEFT, fill=BOTH, expand=1)
    m_scrollbar.pack(side=RIGHT, fill=Y)

    m1_canvas.configure(yscrollcommand=m_scrollbar.set)
    m1_canvas.bind('<Configure>', lambda e:m1_canvas.configure(scrollregion=m1_canvas.bbox("all")))

    m1_canvas.configure(yscrollcommand=m_scrollbar.set)
    m1_canvas.bind('<Configure>', lambda e:m1_canvas.configure(scrollregion=m1_canvas.bbox("all")))

    for widget in thirdS_frame.winfo_children():
                widget.destroy()
                
    for widget in thirdS1_frame.winfo_children():
                widget.destroy()

    #reading UQs in SPARQL
    with open(resource_path('PQs.sparql'),"r") as fileUQ:
        global UQs
        UQs = ""
        for line in fileUQ:
            if line.startswith("SELECT"):
                UQs= UQs+(line[0:])
            if line.startswith("WHERE"):
                UQs= UQs+ ""+ (line[0:])
            if line.startswith("GROUP BY"):
                UQs= UQs+ ""+ (line[0:])
            if line.startswith("TIMEWINDOW"):
                UQs= UQs+ ""+ (line[0:])            
    UQs=UQs.split('SELECT')
    UQs=UQs[1:]

    #reading UQs in text
    with open(resource_path('PQs.txt'),"r") as file:
        global uqss        
        uqss = ""        
        for line in file:            
            if line=='\n':
               line.strip('\n')
            else:
                uqss=uqss+(line[0:])               
    uqss=uqss.split('\n')
    uqqss=uqss[:-1]

    Stree2_frame= Frame(m1_canvas,highlightbackground="darkgrey", highlightthickness=2)
    m1_canvas.create_window((990,45), window=Stree2_frame, anchor="nw")

    Stree2_scroll=Scrollbar(Stree2_frame,orient='vertical')
    Stree2_scroll.pack(side=RIGHT, fill=Y)

    Stree2x_scroll=Scrollbar(Stree2_frame,orient='horizontal')
    Stree2x_scroll.pack(side=BOTTOM, fill=X)


    Stview = ttk.Treeview(Stree2_frame,height=6,yscrollcommand=Stree2_scroll.set,xscrollcommand=Stree2x_scroll.set)
    Stview.pack(expand=YES, fill=BOTH)

    Stree2_scroll.config(command=Stview.yview)
    Stree2x_scroll.config(command=Stview.xview)
    Stview["columns"] = ("1")

    Stview.column("#0",width=80, minwidth=90, anchor=CENTER)
    Stview.column("1", width=780, minwidth=1200)

    Stview.heading("#0", text='Query ID')
    Stview.heading("1", text='Privacy queries that are involved in privacy risks',anchor='nw')


    Stview.tag_configure('oddd',background='lightcyan')
    Stview.tag_configure('evenn',background='lightblue')

    with open(resource_path('suggestions.txt'),"r") as file:
        global UQsugg
        UQsugg = ""
        global PQsugg
        PQsugg=''
        for line in file:
            if line.startswith("Choose"):
                PQsugg= PQsugg+ ""+ (line[0:])
            if line.startswith("Remove"):
                UQsugg= UQsugg+ ""+ (line[0:])
            if line.startswith("Generalize"):
                UQsugg= UQsugg+ ""+ (line[0:])
            if line.startswith("Replace the aggregate"):
                UQsugg= UQsugg+ ""+ (line[0:])
            if line.startswith("Modify"):
                UQsugg= UQsugg+ ""+ (line[0:])
            if line.startswith(">"):
                UQsugg= UQsugg+ ""+ (line[0:])        
        UQNum = re.findall(r'\d+', UQsugg)
        UQNum=sorted(set(UQNum))
        PNum = re.findall(r'\d+', PQsugg)
        PNum=sorted(set(PNum))
        
    for i,j in enumerate(uqss):
        for l in PNum:
            if i==int(l)-1:
                if i%2==0:
                    Stview.insert(parent='', index='end', iid='123'+str(i), text=('PQ'+str(i+1)),open=True, values=([uqss[i]]), tags=('evenn',))
                    for m,n in enumerate(UQs):
                        if m==i:
                            Stview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+UQs[i]]))
                else:
                    Stview.insert(parent='', index='end', iid='123'+str(i), text=('PQ'+str(i+1)),open=True, values=([uqss[i]]), tags=('oddd',))
                    for m,n in enumerate(UQs):              
                        if m==i:
                            Stview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+UQs[i]]))
                    
    #reading suggestions
    with open(resource_path('suggestions.txt'),"r") as file:
        global sugg
        sugg = ""
        global head
        head=""
        for line in file:
            if line.startswith("Choose"):
                head= head+(line[0:])
            if line.startswith("Remove"):
                sugg= sugg+ ""+ (line[0:])
            if line.startswith("Generalize"):
                sugg= sugg+ ""+ (line[0:])
            if line.startswith("Replace the aggregate"):
                sugg= sugg+ ""+ (line[0:])
            if line.startswith("Modify"):
                sugg= sugg+ ""+ (line[0:])
            if line.startswith(">"):
                sugg= sugg+ ""+ (line[0:])
                        
    
    head=head.split('\n')
    head=head[:-1]    
    sugg=sugg.split('>')
    sugg=sugg[:-1]    
    rows=0
    cbss=dict()
    cbsss=dict()
    
    global listck1
    listck1=[]

    #code for removing specific UQ from list
    def deleteUQ():
               
        for name, checkbutton in cbsss.items():            
            if checkbutton.var.get()==True:
                listck1.append(checkbutton)
                deleteUQ= (checkbutton['text'])
                
                for m,n in enumerate(UQNum):
                    if name==n:
                        for x,y in enumerate(lp):            
                            if n==y:               
                                for p,q in enumerate(uqs):            
                                    if p==x:                                      
                                        for k,v in PQlabel.items():                                    
                                            if q==k:
                                                PQlabel[k].config(text=q, fg='powderblue')
                                                for mm,nn in Edits.items():
                                                        if q==mm:                                            
                                                            Edits[mm].config(state=DISABLED)

                        for x,y in enumerate(lp):            
                            if n==y:                    
                                for r,s in enumerate(qp):                                
                                    if r==x:                                    
                                        s=s[:-1]
                                        for k,v in PQlabels.items():                                        
                                                if r==k:
                                                    updatet=''
                                                    PQlabels[k].config(fg="azure2")                                                                                                                                   
                                                    P=''
                                                    LPQQ=[]                                           
                                                    vi= (checkbutton['text'])
                                                    vi=str(vi).partition("for ")[2].partition(".")[0]
                                                    P+=vi                                            
                                                    LPQ=P.split(')')                
                                                    LPQ=LPQ[:-1]                                            
                                                    LPQQ.append(LPQ)
                                            
                                            
                                                    for key, val in cbss.items():                                                 
                                                        for nn in LPQ:
                                                            nn=nn+').'                                                    
                                                            Del=val['text']
                                                            if nn in Del:                                                                
                                                                val.var.set(False)
                                                                cbss[key].config(state=DISABLED)
                                                                

                                                    for key, val in cbsss.items():                                                 
                                                        for nn in LPQ:
                                                            nn=nn+').'                                                    
                                                            Del=val['text']
                                                            if nn in Del:                                                          
                                                                val.var.set(False)
                                                                cbsss[key].config(state=DISABLED)
                                                                checkbutton.var.set(True)
                                                                checkbutton.config(state=NORMAL)
                                                                
                                                    for mm in LPQ:
                                                        twoPQs=mm.find("and")                                                
                                                        if twoPQs!=-1:
                                                            LM=mm.split(' and ')                                               
                                                    
                                                            for key, val in cbss.items():                                                            
                                                                for nm in LM:                                                                
                                                                    nm=nm+').'                                                    
                                                                    Dele=val['text']
                                                                    if nm in Dele:                                                                    
                                                                        val.var.set(False)
                                                                        cbss[key].config(state=DISABLED)
                                                                    
                                                                    
                                                            for key, val in cbsss.items():                                                            
                                                                for nm in LM:                                                                
                                                                    nm=nm+').'   
                                                                    Dele=val['text']
                                                                    if nm in Dele:                                                                    
                                                                        val.var.set(False)
                                                                        cbsss[key].config(state=DISABLED)
                                                                        checkbutton.var.set(True)
                                                                        checkbutton.config(state=NORMAL)
                                                                    
                                            
                                    
        for name, checkbutton in cbsss.items():                              
            if checkbutton.var.get()==False:                                 
                for a in listck1:                                
                    if a==checkbutton:
                        P=''
                        LPQQ=[]                                           
                        vi= (checkbutton['text'])                       
                        vi=str(vi).partition("for ")[2].partition(".")[0]
                        P+=vi                                            
                        LPQ=P.split(')')                
                        LPQ=LPQ[:-1]
                        LPQQ.append(LPQ)
                        for key, val in cbss.items():
                            for nn in LPQ:                                                                    
                                Del=val['text']
                                if nn in Del:                                   
                                    cbss[key].config(state=NORMAL)
                                                              
                                                                         
                                                            
                        for keys,vals in cbsss.items():
                            for nn in LPQ:
                                nn=nn+').'
                                Dele=vals['text']
                                if nn in Dele:                                   
                                    cbsss[keys].config(state=NORMAL)

                        for mm in LPQ:
                            twoPQs=mm.find("and")                                                
                            if twoPQs!=-1:
                                LM=mm.split(' and ')
                                                    
                                                    
                                for key, val in cbss.items():                                                            
                                    for nm in LM:                                                                
                                        nm=nm+').'                                                    
                                        Dele=val['text']
                                        if nm in Dele:      
                                           
                                            cbss[key].config(state=NORMAL)
                                                                    
                                                                    
                                for key, val in cbsss.items():                                                            
                                    for nm in LM:                                                                
                                        nm=nm+').'   
                                        Dele=val['text']
                                        if nm in Dele:                            
                                            cbsss[key].config(state=NORMAL)
                                            
                                    
                        for m,n in enumerate(UQNum):              
                            if name==n:
                                for x,y in enumerate(lp):            
                                    if n==y:               
                                        for p,q in enumerate(uqs):            
                                            if p==x:                
                                                for p,q in enumerate(uqs):                            
                                                    if p==x:
                                                        for k,v in PQlabel.items():                                    
                                                            if q==k:
                               
                                                                PQlabel[k].config(text=q, fg='black')
                                                                for mm,nn in Edits.items():
                                                                    if q==mm:                                            
                                                                        Edits[mm].config(state=NORMAL)
                                for x,y in enumerate(lp):            
                                    if n==y:                    
                                        for r,s in enumerate(qp):                                
                                            if r==x:                                    
                                                s=s[:-1]
                                                for k,v in PQlabels.items():                                        
                                                    if r==k:                                                                            
                                                        PQlabels[k].config(fg="black")
                                                        
                                                
    global listck
    listck=[]
   
    #code for applying modification to UQ
    def modifyUQ():
        modifyUQ=[]
        modifyUQs=[]
        lastval=[]      
        
        
        for name, checkbutton in cbss.items():            
            if checkbutton.var.get()==True:
                lastval.append(checkbutton)
                
        for i in range(0, len(lastval)):
            if i == (len(lastval)-1 ):                 
                for name, checkbutton in cbss.items():                    
                    if (str(lastval[i])==str(checkbutton)) and (checkbutton.var.get()==True):                        
                        listck.append(checkbutton)
                        #removing output variables from UQ
                        modifyUQs= (checkbutton['text'])
                        if str(modifyUQs).startswith("Remove"):
                            modifyUQ = modifyUQs.split()
                            for t in modifyUQ:
                                if(t.startswith("'") and t.endswith("'")):
                                    temp1=t.replace("'",'')
                            for m,n in enumerate(UQNum):                  
                                UQN= 'UQ'+str(n)                           
                                if UQN in name:
                                    for x,y in enumerate(lp):            
                                        if n==y:                    
                                            for r,s in enumerate(qp):                                
                                                if r==x:                                     
                                                    QP=qp[r]
                                                    QP=QP[:-1]                                        
                                                    QP='SELECT'+QP
                                                    groupby= QP.find("GROUP")                                            
                                                    value=QP
                                                    for k,v in PQlabels.items():                                                
                                                        if groupby==-1:
                                                            if r==k:                                                                   
                                                                oldvalue= str(value).partition("SELECT")[2].partition("\n")[0]
                                                                findIndex='SELECT'+oldvalue
                                                                lenTemp1=len(temp1)                                                        
                                                                firstIndex=findIndex.find(temp1)
                                                                lastIndex=firstIndex+lenTemp1
                                                                newvalue= oldvalue.replace(temp1,"")                                                                                                                                                                      
                                                                values= value.replace(temp1,"",1) 
                                                        
                                                        
                                                                                                              
                                                                if values!='SELECT':                                                            
                                                              
                                                                    PQlabels[k].delete('1.0', 'end')
                                                                    PQlabels[k].insert('1.0', value)
                                                                    PQlabels[k].tag_add("start", "1."+str(firstIndex),"1."+str(lastIndex))
                                                                    PQlabels[k].tag_configure("start", background= "white", foreground= "azure2")
                                                                    nqp=values.replace("SELECT", "")                                                        
                                                                    qp[r]=nqp+" "
                                                                   
                                                                    P=''
                                                                    LPQQ=[]                                           
                                                                    vi= (checkbutton['text'])                                                            
                                                                    vi=str(vi).partition("for ")[2].partition(".")[0]
                                                                    P+=vi                                            
                                                                    LPQ=P.split(')')                
                                                                    LPQ=LPQ[:-1]
                                                                    LPQQ.append(LPQ)
                                                                    for key, val in cbss.items():
                                                                        for nn in LPQ:                                                                    
                                                                            Del=val['text']
                                                                            if nn in Del:
                                                                                val.var.set(False)
                                                                                cbss[key].config(state=DISABLED)
                                                                                checkbutton.var.set(True)
                                                                                checkbutton.config(state=NORMAL)     
                                                                         
                                                            
                                                                    for keys,vals in cbsss.items():
                                                                        for nn in LPQ:
                                                                            nn=nn+').'
                                                                            Dele=vals['text']
                                                                            if nn in Dele:
                                                                                vals.var.set(False)
                                                                                cbsss[keys].config(state=DISABLED)
                                                            
                                                                
                                                              
                                                #for k,v in PQlabels.items():                                                
                                                        else:
                                                            if r==k:                                                            
                                                                oldvalue= str(value).partition("SELECT")[2].partition("\n")[0]
                                                                newvalue= oldvalue.replace(temp1,"")
                                                                findIndex='SELECT'+oldvalue
                                                                lenTemp1=len(temp1)                                                        
                                                                firstIndex=findIndex.find(temp1)
                                                                lastIndex=firstIndex+lenTemp1
                                                                values= value.replace(oldvalue, newvalue,1)
                                                                oldgroup= str(value).partition("GROUP BY")[2].partition("\n")[0]
                                                                GIndex='GROUP BY'+oldgroup                                                                                                               
                                                                fIndex=GIndex.find(temp1)
                                                                lIndex=fIndex+lenTemp1+1
                                                                newgroup= oldgroup.replace(temp1,"")                                                        
                                                                values=values.replace(oldgroup,newgroup,1)
                                                       
                                                                if values!='SELECT':
                                                                    PQlabels[k].delete('1.0', 'end')
                                                                    PQlabels[k].insert('1.0', value)
                                                                    PQlabels[k].tag_add("s", "1."+str(firstIndex),"1."+str(lastIndex))
                                                                    PQlabels[k].tag_configure("s", background= "white", foreground= "azure2")
                                                                    PQlabels[k].tag_add("e", "3."+str(fIndex),"3."+str(lIndex))
                                                                    PQlabels[k].tag_configure("e", background= "white", foreground= "azure2")
                                                                    nqp=values.replace("SELECT","")
                                                                    qp[r]=nqp+" "
                                                            
                                                                    P=''
                                                                    LPQQ=[]                                           
                                                                    vi= (checkbutton['text'])
                                                                    vi=str(vi).partition("for ")[2].partition(".")[0]
                                                                    P+=vi                                            
                                                                    LPQ=P.split(')')                
                                                                    LPQ=LPQ[:-1]
                                                                    LPQQ.append(LPQ)
                                                                    for key, val in cbss.items():
                                                                        for nn in LPQ:
                                                                            Del=val['text']
                                                                            if nn in Del:
                                                                                val.var.set(False)
                                                                                cbss[key].config(state=DISABLED)
                                                                                checkbutton.var.set(True)
                                                                                checkbutton.config(state=NORMAL)
                                                            
                                                                    for keys,vals in cbsss.items():
                                                                        for nn in LPQ:
                                                                            nn=nn+').'
                                                                            Dele=vals['text']
                                                                            if nn in Dele:
                                                                                vals.var.set(False)
                                                                                cbsss[keys].config(state=DISABLED)
                                                       
                                                              
                        # generlaizing the property                                               
                        if str(modifyUQs).startswith("Generalize"):
                            modifyUQ = modifyUQs.split()
                            Gen=[]
                            for t in modifyUQ:
                                if(t.startswith("'") and t.endswith("'")):
                                    temp1=t.replace("'",'')
                                    Gen.append(temp1)
                            
                            for m,n in enumerate(UQNum):                        
                                UQN= 'UQ'+str(n)
                                if UQN in name:                                                        
                                        for x,y in enumerate(lp):            
                                            if n==y:                                                
                                                for p,q in enumerate(qp):
                                                    if p==x:
                                                        NPQ=qp[p]                                                       
                                                        NPQ=NPQ[:-1]
                                                        value= 'SELECT'+NPQ                                        
                                                        for k,v in PQlabels.items():
                                                            inp = PQlabels[k].get(1.0, "end-1c")
                                                            s1= str(value).partition("WHERE {")[2].partition("}")[0]
                                                            s2= str(inp).partition("WHERE {")[2].partition("}")[0]                                                                   
                                                            if p==k and s1==s2:                          
                                                 
                                                                msearch= str(value).partition("WHERE {")[2].partition("}")[0]
                                                                yes=msearch.find(Gen[1])
                                                                Gproperty= msearch.split()                                                   
                                                                yes=msearch.find(Gen[1])
                                                    
                                                          
                                                                for m,n in enumerate (Gen):
                                                                    for s,t in enumerate(Gproperty):                                    
                                                    
                                                                        if n==t and yes==-1:
                                                                            iri=(Gen[m+1]).split(':')[0]
                                                                            iri=iri+":"                                                                            
                                                                            Genn=Gen[m+1].replace(iri,"?")                                                               
                                                                            replaceGen1= t + " " + Gproperty[s+1]
                                                                            replaceGen2 = t + " " + Gproperty[s+1] +" . " + Gproperty[s-1] +" "+ Gen[m+1] + " "+ Genn
                                                                            lenGenn=len(Genn)
                                                                            vv=value.replace(Gproperty[s+1],Genn,1)
                                                                            Ind1=vv.find(Genn)                                                                
                                                                            Ind2=Ind1+lenGenn
                                                                            len1=len(Gproperty[s-1])
                                                                            len2=len(Gen[m+1])
                                                                            values=value.replace(Gproperty[s+1],Genn,1)
                                                                            values=values.replace(replaceGen1,replaceGen2)
                                                                            msearch2=str(values).partition("WHERE {")[2].partition("}")[0]
                                                                            Ind3= msearch2.find(Gen[m+1])
                                                                            #print(values)
                                                                            Ind4=Ind3-len1-1+7                                                                
                                                                            Ind5=Ind3+len2+lenGenn+1+7                  
                                                                
                                                                
                                                                            if values!='SELECT':
                                                                                PQlabels[k].delete('1.0', 'end')
                                                                                PQlabels[k].insert('1.0', values)
                                                                                PQlabels[k].tag_add("strt", "1."+str(Ind1),"1."+str(Ind2))                                                        
                                                                                PQlabels[k].tag_add("strt2", "2."+str(Ind4),"2."+str(Ind5))                                                                    
                                                                                PQlabels[k].tag_configure("strt", background= "white", foreground= "darkgreen")
                                                                                PQlabels[k].tag_configure("strt2", background= "white", foreground= "darkgreen")                                                                    
                                                                            
                                                                                nqp=values.replace("SELECT", "")                                                        
                                                                                qp[p]=nqp+" "
                                                                                
                                                                                P=''
                                                                                LPQQ=[]                                           
                                                                                vi= (checkbutton['text'])                                                                    
                                                                                vi=str(vi).partition("for ")[2].partition(".")[0]
                                                                                P+=vi                                            
                                                                                LPQ=P.split(')')                
                                                                                LPQ=LPQ[:-1]
                                                                                LPQQ.append(LPQ)
                                                                                for key, val in cbss.items():
                                                                                    for nn in LPQ:
                                                                                        Del=val['text']
                                                                                        if nn in Del:
                                                                                            val.var.set(False)
                                                                                            cbss[key].config(state=DISABLED)
                                                                                            checkbutton.var.set(True)
                                                                                            checkbutton.config(state=NORMAL)
                                                                                
                                                            
                                                                                for keys,vals in cbsss.items():
                                                                                    for nn in LPQ:
                                                                                        nn=nn+').'
                                                                                        Dele=vals['text']
                                                                                        if nn in Dele:
                                                                                            vals.var.set(False)
                                                                                            cbsss[keys].config(state=DISABLED)
                                                                    
                                                                    
                                                                                                                               
                                                                

                        #Replacing the aggregate in UQ      
                        if str(modifyUQs).startswith("Replace the aggregate"):
                                         

                            Aggr_window = Toplevel(master)               

                            Aggr_window .geometry('155x90+250+450')    
                            Aggr_window .title("Replace aggregate")
                            
                            frame1 = Frame(Aggr_window,width=155,height=90)
                            frame1.grid(row=1)
 
                            # Frame 2
                            frame2 = Frame(Aggr_window,width=155,height=90)
                            frame2.grid(row=3)
 
                            Aggr_label= Label(frame1 , text='Aggregate:')
                            Aggr_label.grid(row=1,column=0, sticky='w', pady=2)                            

                            modifyUQ = modifyUQs.split()
                            Agr=[]
                            for t in modifyUQ:
                                if(t.startswith("'") and t.endswith("'")):
                                    temp1=t.replace("'",'')
                                    Agr.append(temp1)
                                    

                            def pick_agg():                    
                                for m,n in enumerate(UQNum):                        
                                    UQN= 'UQ'+str(n)
                                    if UQN in name:
                                        for p,q in enumerate(qp):                                           
                                            APQ=qp[p]
                                            APQ=APQ[:-1]
                                            value= 'SELECT'+APQ
                                            
                                            for k,v in PQlabels.items():
                                                inp = PQlabels[k].get(1.0, "end-1c")                                                
                                                if temp1[0] in inp:                                              
                                                    if value==inp:                                                                                                  
                                                        aggre=Aggr_dropdown.get()                                          
                                                        values=value.replace(Agr[0], Aggr_dropdown.get(),1)
                                                        if values!='SELECT':
                                                            lenTemp1=len(aggre)                                                        
                                                            firstIndex=values.find(aggre)
                                                            lastIndex=firstIndex+lenTemp1
                                                            PQlabels[k].delete('1.0', 'end')
                                                            PQlabels[k].insert('1.0', values)
                                                            PQlabels[k].tag_add("start", "1."+str(firstIndex),"1."+str(lastIndex))
                                                            PQlabels[k].tag_configure("start", background= "white", foreground= "darkgreen")                                                
                                                            
                                                            
                                                            nqp=values.replace("SELECT", "")                                                        
                                                            qp[p]=nqp+" "
                                                            
                                                            P=''
                                                            LPQQ=[]                                           
                                                            vi= (checkbutton['text'])                                                            
                                                            vi=str(vi).partition("for ")[2].partition(".")[0]
                                                            P+=vi                                            
                                                            LPQ=P.split(')')                
                                                            LPQ=LPQ[:-1]
                                                            LPQQ.append(LPQ)
                                                            for key, val in cbss.items():
                                                                        for nn in LPQ:
                                                                            Del=val['text']
                                                                            if nn in Del:
                                                                                val.var.set(False)
                                                                                cbss[key].config(state=DISABLED)
                                                                                checkbutton.var.set(True)
                                                                                checkbutton.config(state=NORMAL)
                                                            
                                                            for keys,vals in cbsss.items():
                                                                        for nn in LPQ:
                                                                            nn=nn+').'
                                                                            Dele=vals['text']
                                                                            if nn in Dele:
                                                                                vals.var.set(False)
                                                                                cbsss[keys].config(state=DISABLED)                                                           
                                                        
                                Aggr_window.destroy()                                                        
                                                        
                            Aggs = [
                            Agr[1],                    
                            Agr[2]]
                            Aggr_dropdown = StringVar()
                            Aggr_dropdown= ttk.Combobox(frame1 , textvariable='',value=Aggs, width=6)
                            Aggr_dropdown.grid(row=1,column=2, sticky='w', pady=2)
                            Aggr_dropdown.current(0)
                            #Aggr_dropdown.bind("<<ComboboxSelected>>")

                            Asave_btn = ttk.Button(frame2, text="Save",width=6,command=pick_agg)
                            Asave_btn.grid(row=3, padx=43, pady=15)

                            Aggr_window.mainloop()
                            
                        #modifing the time window                    
                        if str(modifyUQs).startswith("Modify"):                   
                            TW_window = Toplevel(master)
                            #Create an instance of tkinter frame or window


                            #Define the geometry
                            TW_window .geometry('250x130+250+450')    
                            TW_window .title("Modify time window")

                            def pick_time():                    
                                for m,n in enumerate(UQNum):                        
                                    UQN= 'UQ'+str(n)
                                    if UQN in name:                                                            
                                        for p,q in enumerate(qp):                                                                
                                            TPQ=qp[p]
                                            TPQ=TPQ[:-1]
                                            value= 'SELECT'+TPQ
                                            for k,v in PQlabels.items():
                                                inp = PQlabels[k].get(1.0, "end-1c")                                                
                                                if 'TIMEWINDOW' in inp:                                              
                                                    if value==inp:                                                 
                                                        oldtime= str(value).partition("TIMEWINDOW (")[2].partition(")")[0]
                                                        newtime=size_entry.get()+TSize_dropdown.get()+ ", " +step_entry.get()+TStep_dropdown.get()
                                                        Tsize=size_entry.get()+TSize_dropdown.get()
                                                        Tstep=step_entry.get()+TStep_dropdown.get()
                                                        values=value.replace(oldtime, newtime,1)
                                                        searchtime=str(values).partition("TIMEWINDOW (")[2].partition(")")[0]
                                                        T1=searchtime.find(Tsize)
                                                        lenTsize=len(Tsize)
                                                        T1=searchtime.find(Tsize)
                                                        Ind1=T1+12
                                                        Ind2=T1+lenTsize+12
                                                        lenTstep=len(Tstep)
                                                        T2=searchtime.find(Tstep)
                                                        Ind3=T2+12
                                                        Ind4=T2+lenTstep+12
                                                        
                                                        if q!='': 
                                                           
                                                            PQlabels[k].delete('1.0', 'end')
                                                            PQlabels[k].insert('1.0', values)
                                                            PQlabels[k].tag_add("timestep", "4."+str(Ind1),"4."+str(Ind2))
                                                            PQlabels[k].tag_add("timesize", "4."+str(Ind3),"4."+str(Ind4))                                                            
                                                            PQlabels[k].tag_configure("timestep", background= "white", foreground= "darkgreen")
                                                            PQlabels[k].tag_configure("timesize", background= "white", foreground= "darkgreen")
                                                            nqp=values.replace("SELECT", "")                                                        
                                                            qp[p]=nqp+" "
                                                            
                                                            P=''
                                                            LPQQ=[]                                           
                                                            vi= (checkbutton['text'])
                                                            vi=str(vi).partition("for ")[2].partition(".")[0]
                                                            P+=vi                                            
                                                            LPQ=P.split(')')                
                                                            LPQ=LPQ[:-1]
                                                            LPQQ.append(LPQ)
                                                            for key, val in cbss.items():
                                                                        for nn in LPQ:
                                                                            Del=val['text']
                                                                            if nn in Del:
                                                                                val.var.set(False)
                                                                                cbss[key].config(state=DISABLED)
                                                                                checkbutton.var.set(True)
                                                                                checkbutton.config(state=NORMAL)
                                                            
                                                            for keys,vals in cbsss.items():
                                                                        for nn in LPQ:
                                                                            nn=nn+').'
                                                                            Dele=vals['text']
                                                                            if nn in Dele:
                                                                                vals.var.set(False)
                                                                                cbsss[keys].config(state=DISABLED)                                                                  
                        
                                TW_window.destroy()
                                
                            framet1 = Frame(TW_window,width=250,height=130)
                            framet1.grid()
 
                            # Frame 2 for creating window for modifying timewindow
                            framet2 = Frame(TW_window,width=250,height=130)
                            framet2.grid(row=4)                 

                            size_label= Label(framet1 , text='Time window size:')
                            size_label.grid(row=1,column=0, sticky='w', pady=2)
                
                            size_entry= Entry(framet1 , width=5)
                            size_entry.grid(row=1,column=1, sticky='w', pady=2)

                            Time = [
                                "h",
                                "m",
                                "s"                    
                                ]
                            TSize_dropdown = StringVar()
                            TSize_dropdown= ttk.Combobox(framet1 , textvariable='',value=Time, width=5)
                            TSize_dropdown.grid(row=1,column=2, sticky='w', pady=2)
                            TSize_dropdown.current(0)                    

                            step_label= Label(framet1 , text='Time window step:')
                            step_label.grid(row=2,column=0, sticky='w', pady=2)

                            step_entry= Entry(framet1 , width=5)
                            step_entry.grid(row=2, column=1, sticky='w', pady=2)
                        
                            TStep_dropdown = StringVar()
                            TStep_dropdown= ttk.Combobox(framet1 , textvariable='',value=Time, width=5)
                            TStep_dropdown.grid(row=2,column=2, sticky='w', pady=2)
                            TStep_dropdown.current(0)
                            

                            Tsave_btn = ttk.Button(framet2, text="Save",width=6,command=pick_time)
                            Tsave_btn.grid(row=4, padx=70, pady=15)

                            TW_window.mainloop()
            
                
        # reversing the modification made to UQ if button is unchecked                                                          
        for name, checkbutton in cbss.items():            
            if checkbutton.var.get()==False:                                 
                            for a in listck:                                
                                if a==checkbutton:                                    
                                    P=''
                                    LPQQ=[]                                           
                                    vi= (checkbutton['text'])
                                    vi=str(vi).partition("for ")[2].partition(".")[0]
                                    P+=vi                                            
                                    LPQ=P.split(')')                
                                    LPQ=LPQ[:-1]
                                    LPQQ.append(LPQ)
                                    for key, val in cbss.items():
                                        for nn in LPQ:                                                                    
                                            Del=val['text']
                                            if nn in Del:                                                
                                                cbss[key].config(state=NORMAL)                                                     
                                                                         
                                                            
                                    for keys,vals in cbsss.items():
                                            for nn in LPQ:
                                                nn=nn+').'
                                                Dele=vals['text']
                                                if nn in Dele:                                                    
                                                    cbsss[keys].config(state=NORMAL)
                                    
                                    for a,b in enumerate(origqp):
                                        for e,f in enumerate(qp):
                                            if a==e:
                                                qp[e]=origqp[a]                                                
                                        for c,d in PQlabels.items():                                            
                                            if a==c:
                                                    QPP=origqp[a]                                                
                                                    QPP=QPP[:-1]                                        
                                                    QPP='SELECT'+QPP                                                                                       
                                                    PQlabels[c].delete('1.0', 'end')
                                                    PQlabels[c].insert('1.0', QPP)                                                                                               
                                    
                                               
                                    for name, checkbutton in cbss.items():                                                       
                                        if(checkbutton.var.get()==True):                                             
                                            modifyUQs= (checkbutton['text'])
                                            if str(modifyUQs).startswith("Remove"):
                                                modifyUQ = modifyUQs.split()
                                                for t in modifyUQ:
                                                    if(t.startswith("'") and t.endswith("'")):
                                                        temp1=t.replace("'",'')
                                                for m,n in enumerate(UQNum):                  
                                                    UQN= 'UQ'+str(n)                           
                                                    if UQN in name:                                                   
                                                        for x,y in enumerate(lp):            
                                                            if n==y:                   
                                              
                                                                for r,s in enumerate(qp):
                                                                    if r==x:
                                                                        QP=qp[r]                                                                
                                                                        QP=QP[:-1]                                        
                                                                        QP='SELECT'+QP
                                                                        groupby= QP.find("GROUP")
                                                                        value=QP
                                                                        for k,v in PQlabels.items():                                                
                                                                            if groupby==-1:
                                                                                if r==k:
                                                                                    oldvalue= str(value).partition("SELECT")[2].partition("\n")[0]
                                                                                    findIndex='SELECT'+oldvalue
                                                                                    lenTemp1=len(temp1)                                                        
                                                                                    firstIndex=findIndex.find(temp1)
                                                                                    lastIndex=firstIndex+lenTemp1                                                                                                                                                                    
                                                                                    newvalue= oldvalue.replace(temp1,"")                                                                                                                                                            
                                                                                    values= value.replace(temp1,"",1)       
                                                                                                                                 
                                                                                    if values!='SELECT':                                                            
                                                            
                                                                                        PQlabels[k].delete('1.0', 'end')
                                                                                        PQlabels[k].insert('1.0', value)
                                                                                        PQlabels[k].tag_add("start", "1."+str(firstIndex),"1."+str(lastIndex))
                                                                                        PQlabels[k].tag_configure("start", background= "white", foreground= "azure2")
                                                                                        nqp=values.replace("SELECT", "")                                                         
                                                                                        qp[r]=nqp+" "
                                                                                
                                                                                        P=''
                                                                                        LPQQ=[]                                           
                                                                                        vi= (checkbutton['text'])
                                                                                        vi=str(vi).partition("for ")[2].partition(".")[0]
                                                                                        P+=vi                                            
                                                                                        LPQ=P.split(')')                
                                                                                        LPQ=LPQ[:-1]
                                                                                        LPQQ.append(LPQ)
                                                                                        for key, val in cbss.items():
                                                                                            for nn in LPQ:                                                                    
                                                                                                Del=val['text']
                                                                                                if nn in Del:
                                                                                                    val.var.set(False)
                                                                                                    cbss[key].config(state=DISABLED)
                                                                                                    checkbutton.var.set(True)
                                                                                                    checkbutton.config(state=NORMAL)
       
                                                                         
                                                            
                                                                                        for keys,vals in cbsss.items():
                                                                                            for nn in LPQ:
                                                                                                nn=nn+').'
                                                                                                Dele=vals['text']
                                                                                                if nn in Dele:
                                                                                                    vals.var.set(False)
                                                                                                    cbsss[keys].config(state=DISABLED)
                                                                                            
                                                            
                                                                
                                                                                                                   
                                                                            else:
                                                                                if r==k:                                                            
                                                                                    oldvalue= str(value).partition("SELECT")[2].partition("\n")[0]
                                                                                    newvalue= oldvalue.replace(temp1,"")
                                                                                    findIndex='SELECT'+oldvalue
                                                                                    lenTemp1=len(temp1)                                                        
                                                                                    firstIndex=findIndex.find(temp1)
                                                                                    lastIndex=firstIndex+lenTemp1
                                                                                    values= value.replace(oldvalue, newvalue,1)
                                                                                    oldgroup= str(value).partition("GROUP BY")[2].partition("\n")[0]
                                                                                    GIndex='GROUP BY'+oldgroup                                                                                                               
                                                                                    fIndex=GIndex.find(temp1)
                                                                                    lIndex=fIndex+lenTemp1+1
                                                                                    newgroup= oldgroup.replace(temp1,"")                                                        
                                                                                    values=values.replace(oldgroup,newgroup,1)
                                                        
                                                                                    if values!='SELECT':
                                                                                        PQlabels[k].delete('1.0', 'end')
                                                                                        PQlabels[k].insert('1.0', value)
                                                                                        PQlabels[m].tag_add("s", "1."+str(firstIndex),"1."+str(lastIndex))
                                                                                        PQlabels[m].tag_configure("s", background= "white", foreground= "azure2")
                                                                                        PQlabels[m].tag_add("e", "3."+str(fIndex),"3."+str(lIndex))
                                                                                        PQlabels[m].tag_configure("e", background= "white", foreground= "azure2")
                                                                                        nqp=values.replace("SELECT","")
                                                                                        qp[r]=nqp+" "
                                                            
                                                                                        P=''
                                                                                        LPQQ=[]                                           
                                                                                        vi= (checkbutton['text'])
                                                                                        vi=str(vi).partition("for ")[2].partition(".")[0]
                                                                                        P+=vi                                            
                                                                                        LPQ=P.split(')')                
                                                                                        LPQ=LPQ[:-1]
                                                                                        LPQQ.append(LPQ)
                                                                                        for key, val in cbss.items():
                                                                                            for nn in LPQ:
                                                                                                Del=val['text']
                                                                                                if nn in Del:
                                                                                                    val.var.set(False)
                                                                                                    cbss[key].config(state=DISABLED)
                                                                                                    checkbutton.var.set(True)
                                                                                                    checkbutton.config(state=NORMAL)
                                                            
                                                                                        for keys,vals in cbsss.items():
                                                                                            for nn in LPQ:
                                                                                                nn=nn+').'
                                                                                                Dele=vals['text']
                                                                                                if nn in Dele:
                                                                                                    vals.var.set(False)
                                                                                                    cbsss[keys].config(state=DISABLED)
                                                                        
                                            if str(modifyUQs).startswith("Generalize"):
                                                modifyUQ = modifyUQs.split()
                                                Gen=[]
                                                for t in modifyUQ:
                                                    if(t.startswith("'") and t.endswith("'")):
                                                        temp1=t.replace("'",'')
                                                        Gen.append(temp1)
                                                for m,n in enumerate(UQNum):                        
                                                    UQN= 'UQ'+str(n)
                                                    if UQN in name:                                                        
                                                        for x,y in enumerate(lp):            
                                                            if n==y:                                                
                                                                for p,q in enumerate(qp):
                                                                    if p==x:
                                                                        NPQ=qp[p]
                                                                       
                                                                        NPQ=NPQ[:-1]
                                                                        value= 'SELECT'+NPQ                                        
                                                                        for k,v in PQlabels.items():
                                                                            inp = PQlabels[k].get(1.0, "end-1c")
                                                                            s1= str(value).partition("WHERE {")[2].partition("}")[0]
                                                                            s2= str(inp).partition("WHERE {")[2].partition("}")[0]                                                                   
                                                                            if p==k and s1==s2:
                                                                               
                                                                                msearch= str(value).partition("WHERE {")[2].partition("}")[0]
                                                                                Gproperty= msearch.split()
                                                                                
                                                                                yes=msearch.find(Gen[1])
                                                          
                                                                                for m,n in enumerate (Gen):
                                                                                    for s,t in enumerate(Gproperty):                                    
                                                    
                                                                                        if n==t and yes==-1:
                                                                                            iripre=(Gen[m+1]).split(':')[0]
                                                                                            iripre=iripre+":"                                                                            
                                                                                            Genn=Gen[m+1].replace(iripre,"?")                                                                                                                                                  
                                                                                            replaceGen1= t + " " + Gproperty[s+1]
                                                                                            replaceGen2 = t + " " + Gproperty[s+1] +" . " + Gproperty[s-1] +" "+ Gen[m+1] + " "+ Genn
                                                                                            lenGenn=len(Genn)
                                                                                            vv=value.replace(Gproperty[s+1],Genn,1)
                                                                                            Ind1=vv.find(Genn)                                                                
                                                                                            Ind2=Ind1+lenGenn
                                                                                            len1=len(Gproperty[s-1])
                                                                                            len2=len(Gen[m+1])
                                                                                            values=value.replace(Gproperty[s+1],Genn,1)
                                                                                            values=values.replace(replaceGen1,replaceGen2)
                                                                                            msearch2=str(values).partition("WHERE {")[2].partition("}")[0]
                                                                                            Ind3= msearch2.find(Gen[m+1])                                                                    
                                                                                            Ind4=Ind3-len1-1+7                                                                
                                                                                            Ind5=Ind3+len2+lenGenn+1+7         
                                                                
                                                                
                                                                                            if values!='SELECT':
                                                                                                PQlabels[k].delete('1.0', 'end')
                                                                                                PQlabels[k].insert('1.0', values)
                                                                                                PQlabels[k].tag_add("strt", "1."+str(Ind1),"1."+str(Ind2))                                                        
                                                                                                PQlabels[k].tag_add("strt2", "2."+str(Ind4),"2."+str(Ind5))                                                                    
                                                                                                PQlabels[k].tag_configure("strt", background= "white", foreground= "darkgreen")
                                                                                                PQlabels[k].tag_configure("strt2", background= "white", foreground= "darkgreen")                                                                    
                                                                                                
                                                                                                nqp=values.replace("SELECT", "")                                                        
                                                                                                qp[p]=nqp+" "
                                                                        
                                                                                                P=''
                                                                                                LPQQ=[]                                           
                                                                                                vi= (checkbutton['text'])
                                                                                                vi=str(vi).partition("for ")[2].partition(".")[0]
                                                                                                P+=vi                                            
                                                                                                LPQ=P.split(')')                
                                                                                                LPQ=LPQ[:-1]
                                                                                                LPQQ.append(LPQ)
                                                                                                for key, val in cbss.items():
                                                                                                    for nn in LPQ:
                                                                                                        Del=val['text']
                                                                                                        if nn in Del:
                                                                                                            val.var.set(False)
                                                                                                            cbss[key].config(state=DISABLED)
                                                                                                            checkbutton.var.set(True)
                                                                                                            checkbutton.config(state=NORMAL)
                                                                                
                                                            
                                                                                                for keys,vals in cbsss.items():
                                                                                                    for nn in LPQ:
                                                                                                        nn=nn+').'
                                                                                                        Dele=vals['text']
                                                                                                        if nn in Dele:
                                                                                                            vals.var.set(False)
                                                                                                            cbsss[keys].config(state=DISABLED)

                                            if str(modifyUQs).startswith("Replace the aggregate"):
                                         

                                                Aggr_window = Toplevel(master)                      

                                                Aggr_window = Toplevel(master)               

                                                Aggr_window .geometry('155x90+250+450')    
                                                Aggr_window .title("Replace aggregate")
                            
                                                frame1 = Frame(Aggr_window,width=155,height=90)
                                                frame1.grid(row=1)
 
                           
                                                frame2 = Frame(Aggr_window,width=155,height=90)
                                                frame2.grid(row=3)
 
                                                Aggr_label= Label(frame1 , text='Aggregate:')
                                                Aggr_label.grid(row=1,column=0, sticky='w', pady=2)

                                                modifyUQ = modifyUQs.split()
                                                Agr=[]
                                                for t in modifyUQ:
                                                    if(t.startswith("'") and t.endswith("'")):
                                                        temp1=t.replace("'",'')
                                                        Agr.append(temp1)
                                                        
                                                def pick_agg(e):
                                                    for m,n in enumerate(UQNum):                        
                                                        UQN= 'UQ'+str(n)
                                                        if UQN in name:
                                                            for p,q in enumerate(qp):                                                                                                      
                                                                APQ=qp[p]
                                                                APQ=APQ[:-1]
                                                                value= 'SELECT'+APQ 
                                                                for k,v in PQlabels.items():                                                                            
                                                                    inp = PQlabels[k].get(1.0, "end-1c")                                                
                                                                    if temp1[0] in inp:                                              
                                                                        if value==inp:                
                                                                                aggre=Aggr_dropdown.get()                                          
                                                                                values=value.replace(Agr[0], Aggr_dropdown.get(),1)
                                                                                if values!='SELECT':
                                                                                    lenTemp1=len(aggre)                                                        
                                                                                    firstIndex=values.find(aggre)
                                                                                    lastIndex=firstIndex+lenTemp1
                                                                                    PQlabels[k].delete('1.0', 'end')
                                                                                    PQlabels[k].insert('1.0', values)
                                                                                    PQlabels[k].tag_add("start", "1."+str(firstIndex),"1."+str(lastIndex))
                                                                                    PQlabels[k].tag_configure("start", background= "white", foreground= "darkgreen")                               
                                                            
                                                                                    nqp=values.replace("SELECT", "")                                                        
                                                                                    qp[p]=nqp+" "                                                                                    
                                                                                    P=''
                                                                                    LPQQ=[]                                           
                                                                                    vi= (checkbutton['text'])
                                                                                    vi=str(vi).partition("for ")[2].partition(".")[0]
                                                                                    P+=vi                                            
                                                                                    LPQ=P.split(')')                
                                                                                    LPQ=LPQ[:-1]
                                                                                    LPQQ.append(LPQ)
                                                                                    for key, val in cbss.items():
                                                                                        for nn in LPQ:
                                                                                            Del=val['text']
                                                                                            if nn in Del:
                                                                                                val.var.set(False)
                                                                                                cbss[key].config(state=DISABLED)
                                                                                                checkbutton.var.set(True)
                                                                                                checkbutton.config(state=NORMAL)
                                                            
                                                                                    for keys,vals in cbsss.items():
                                                                                        for nn in LPQ:
                                                                                            nn=nn+').'
                                                                                            Dele=vals['text']
                                                                                            if nn in Dele:
                                                                                                vals.var.set(False)
                                                                                                cbsss[keys].config(state=DISABLED)                                                           
                                                        
                                                        
                                                    Aggr_window.destroy()        
                                                Aggs = [
                                                Agr[1],                    
                                                Agr[2]]
                                                Aggr_dropdown = StringVar()
                                                Aggr_dropdown= ttk.Combobox(frame1 , textvariable='',value=Aggs, width=6)
                                                Aggr_dropdown.grid(row=1,column=2, sticky='w', pady=2)
                                                Aggr_dropdown.current(0)
                                                

                                                Asave_btn = ttk.Button(frame2, text="Save",width=6,command=pick_agg)
                                                Asave_btn.grid(row=3, padx=43, pady=15)          

                                                Aggr_window.mainloop()
                                                
                                            if str(modifyUQs).startswith("Modify"):                   
                                                TW_window = Toplevel(master)
                                                #Create an instance of tkinter frame or window

                                                #Define the geometry
                                                TW_window .geometry('250x130+250+450')    
                                                TW_window .title("Modify time window")

                                                def pick_time():                    
                                                    for m,n in enumerate(UQNum):                        
                                                        UQN= 'UQ'+str(n)
                                                        if UQN in name:                                                            
                                                            for p,q in enumerate(qp):                                                                
                                                                TPQ=qp[p]
                                                                TPQ=TPQ[:-1]
                                                                value= 'SELECT'+TPQ
                                                                for k,v in PQlabels.items():
                                                                    inp = PQlabels[k].get(1.0, "end-1c")                                                
                                                                    if 'TIMEWINDOW' in inp:                                              
                                                                        if value==inp:                                                                
                                                                                                                
                                                                            oldtime= str(value).partition("TIMEWINDOW (")[2].partition(")")[0]
                                                                            newtime=size_entry.get()+TSize_dropdown.get()+ ", " +step_entry.get()+TStep_dropdown.get()
                                                                            Tsize=size_entry.get()+TSize_dropdown.get()
                                                                            Tstep=step_entry.get()+TStep_dropdown.get()
                                                                            values=value.replace(oldtime, newtime,1)
                                                                            searchtime=str(values).partition("TIMEWINDOW (")[2].partition(")")[0]
                                                                            T1=searchtime.find(Tsize)
                                                                            lenTsize=len(Tsize)
                                                                            T1=searchtime.find(Tsize)
                                                                            Ind1=T1+12
                                                                            Ind2=T1+lenTsize+12
                                                                            lenTstep=len(Tstep)
                                                                            T2=searchtime.find(Tstep)
                                                                            Ind3=T2+12
                                                                            Ind4=T2+lenTstep+12
                                                        
                                                                            if q!='': 
                                                                                
                                                                                PQlabels[k].delete('1.0', 'end')
                                                                                PQlabels[k].insert('1.0', values)
                                                                                PQlabels[k].tag_add("timestep", "4."+str(Ind1),"4."+str(Ind2))
                                                                                PQlabels[k].tag_add("timesize", "4."+str(Ind3),"4."+str(Ind4))                                                            
                                                                                PQlabels[k].tag_configure("timestep", background= "white", foreground= "darkgreen")
                                                                                PQlabels[k].tag_configure("timesize", background= "white", foreground= "darkgreen")
                                                                                nqp=values.replace("SELECT", "")                                                        
                                                                                qp[p]=nqp+" "
                                                                                
                                                                                P=''
                                                                                LPQQ=[]                                           
                                                                                vi= (checkbutton['text'])
                                                                                vi=str(vi).partition("for ")[2].partition(".")[0]
                                                                                P+=vi                                            
                                                                                LPQ=P.split(')')                
                                                                                LPQ=LPQ[:-1]
                                                                                LPQQ.append(LPQ)
                                                                                for key, val in cbss.items():
                                                                                    for nn in LPQ:
                                                                                        Del=val['text']
                                                                                        if nn in Del:
                                                                                            val.var.set(False)
                                                                                            cbss[key].config(state=DISABLED)
                                                                                            checkbutton.var.set(True)
                                                                                            checkbutton.config(state=NORMAL)
                                                            
                                                                                for keys,vals in cbsss.items():
                                                                                    for nn in LPQ:
                                                                                        nn=nn+').'
                                                                                        Dele=vals['text']
                                                                                        if nn in Dele:
                                                                                            vals.var.set(False)
                                                                                            cbsss[keys].config(state=DISABLED)                                 
                                                                                
                        
                                                    TW_window.destroy()

                                                    
                                                framet1 = Frame(TW_window,width=250,height=130)
                                                framet1.grid()
 
                                                # Frame 2
                                                framet2 = Frame(TW_window,width=250,height=130)
                                                framet2.grid(row=4)                 

                                                size_label= Label(framet1 , text='Time window size:')
                                                size_label.grid(row=1,column=0, sticky='w', pady=2)
                
                                                size_entry= Entry(framet1 , width=5)
                                                size_entry.grid(row=1,column=1, sticky='w', pady=2)

                                                Time = [
                                                    "h",
                                                    "m",
                                                    "s"                    
                                                    ]
                                                TSize_dropdown = StringVar()
                                                TSize_dropdown= ttk.Combobox(framet1 , textvariable='',value=Time, width=5)
                                                TSize_dropdown.grid(row=1,column=2, sticky='w', pady=2)
                                                TSize_dropdown.current(0)                    

                                                step_label= Label(framet1 , text='Time window step:')
                                                step_label.grid(row=2,column=0, sticky='w', pady=2)

                                                step_entry= Entry(framet1 , width=5)
                                                step_entry.grid(row=2, column=1, sticky='w', pady=2)
                        
                                                TStep_dropdown = StringVar()
                                                TStep_dropdown= ttk.Combobox(framet1 , textvariable='',value=Time, width=5)
                                                TStep_dropdown.grid(row=2,column=2, sticky='w', pady=2)
                                                TStep_dropdown.current(0)
                                            

                                                Tsave_btn = ttk.Button(framet2, text="Save",width=6,command=pick_time)
                                                Tsave_btn.grid(row=4, padx=70, pady=15)
                                                TW_window.mainloop()

    #change the UQs on main window
    def Apply():
        for item in treev.get_children():
              treev.delete(item)  

        listR=[]                                                            
        for a,b in enumerate(origqp):
            for e,f in enumerate(qp):
                if a==e:
                    RQ=qp[e]
                    listR.append(RQ)
                    qp[e]=origqp[a]
           
                                                                                                    
        for name, checkbutton in cbss.items():            
            if checkbutton.var.get():                
                            for r,s in enumerate(qp):                                
                                for w,x in enumerate(listR):                                     
                                        if r==w:
                                            QP=qp[r]
                                            QP=QP[:-1]                                        
                                            QP='SELECT'+QP
                                            groupby= QP.find("GROUP")
                                            value=QP                                          
                                            values= 'SELECT'+listR[w]                                                                                      
                                                                        
                                            with open(resource_path('UQs.sparql'),"r+") as file:
                                                                dataPQ=file.read()                                                                                                                               
                                                                v=(value).replace("?",r"\?")
                                                                p= (values).replace("?",r"\?")                            
                                                                p=p.replace("(",r"\(")
                                                                p=p.replace(")",r"\)")
                                                                v=v.replace("(",r"\(")
                                                                v=v.replace(")",r"\)")
                                                                dataPQ = re.sub(v, p,dataPQ)
                                                                dataPQ=dataPQ.replace('\\','')
                                                                file.seek(0)
                                                                file.truncate()
                                                                file.write(dataPQ)
        #Updating utility queries in the file
        for name, checkbutton in cbsss.items():
            if checkbutton.var.get():                
                deleteUQ= (checkbutton['text'])               
                for m,n in enumerate(UQNum):                                                                 
                    if name==n:
                        for x,y in enumerate(lp):            
                            if n==y:               
                                for r,s in enumerate(qp):            
                                    if r==x:
                                        s=s[:-1]                                                                         
                                        with open(resource_path('UQs.sparql'),"r+") as f:
                                                data=f.read()                                                
                                                v1=""
                                                s= 'SELECT' +s                                                
                                                p1=(s).replace("?",r"\?")
                                                p1=p1.replace("(",r"\(")
                                                p1=p1.replace(")",r"\)")                                                
                                                data = re.sub(p1,v1, data)                                                
                                                data=data.replace('\\','')
                                                f.seek(0)
                                                f.truncate()
                                                f.write(data)
                                                
                                for p,q in enumerate(uqs):
                                    if p==x:
                                        with open(resource_path('UQs.txt'),"r+") as f:
                                            data=f.read()
                                            v='UQ'+str(n)
                                            v1=""
                                            p1= (q).replace("?",r"\?")
                                            data = re.sub(p1, v1, data)
                                            data = re.sub(v, v1, data)
                                            f.seek(0)
                                            f.truncate()
                                            f.write(data)

        with open(resource_path('UQs.sparql'),"r") as fileUQ:
                                                        
                                                        U_UQ = ""
                                                        FUQ=""
                                                        for line in fileUQ:
                                                            if line.startswith("UQ"):
                                                                FUQ= FUQ+(line[0:])
                                                            if line.startswith("SELECT"):
                                                                U_UQ = U_UQ +(line[0:])
                                                            if line.startswith("WHERE"):
                                                                U_UQ = U_UQ + ""+ (line[0:])
                                                            if line.startswith("GROUP BY"):
                                                                U_UQ = U_UQ + ""+ (line[0:])
                                                            if line.startswith("TIMEWINDOW"):
                                                                U_UQ = U_UQ + ""+ (line[0:])
                                                                
        U_UQ =U_UQ .split('SELECT')
        U_UQ =U_UQ [1:]
        FUQ=FUQ.split('\n')

        #reading UQs in text
        with open(resource_path('UQs.txt'),"r") as file:                                                        
                                                        m_uq = ""
                                                        s_sp=""
                                                        fsp=""
                                                        for i,j in enumerate(file):
                                                            if i>0 and j.startswith("I"):
                                                                m_uq= m_uq+(j[0:])
                                                            if i>0 and j.startswith("U"):
                                                                fsp= fsp+(j[0:]) 
                                                            if i==0:
                                                                s_sp= s_sp+(j[0:])           
        m_uq=m_uq.split('\n')
        fsp=fsp.split('\n')

        for item in tview.get_children():
                    tview.delete(item)
                            
        for i,j in enumerate(m_uq):
                            for s,t in enumerate(fsp):
                                                    if i%2==0:
                                                        if i==s:
                                                            tview.insert(parent='', index='end', iid='123'+str(i), text=(t), values=([m_uq[i]]), tags=('even',))
                                                            for m,n in enumerate(U_UQ):                                    
                                                                if m==i:
                                                                    tview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+U_UQ[i]]))
                                                    else:
                                                        if i==s:
                                                            tview.insert(parent='', index='end', iid='123'+str(i), text=(t), values=([m_uq[i]]), tags=('odd',))
                                                            for m,n in enumerate(U_UQ):              
                                                                if m==i:
                                                                    tview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+U_UQ[i]]))
                                                        
                        
                                                    
        gui_window1.destroy()                                            
                                                        
    #reading UQs in text
    with open(resource_path('UQs.txt'),"r") as file:
        #global uqs
        uqs = ""
        sp=""
        lp=""
        for i,j in enumerate(file):
            if i>0 and j.startswith("I"):
                uqs= uqs+(j[0:])
            if i>0 and j.startswith("UQ"):
                lp= lp+(j[0:])
            if i==0:
               sp= sp+(j[0:])           
    uqs=uqs.split('\n')
    lp=str(lp).replace('UQ','')    
    lp=lp.split('\n')
    lp=lp[:-1]                         
    
    with open(resource_path('UQs.sparql'),"r") as file:
        global qp
        qp = ""
        global origqp
        origqp=''
        global replaceqp
        replaceqp=''
        for line in file:
            if line.startswith("SELECT"):
                qp= qp+(line[0:])
                origqp= origqp+(line[0:])
            if line.startswith("WHERE"):
                qp= qp+ ""+ (line[0:])
                origqp= origqp+(line[0:])
                replaceqp= replaceqp+(line[0:])
            if line.startswith("GROUP BY"):
                qp= qp+ ""+ (line[0:])
                origqp= origqp+(line[0:])
                replaceqp=replaceqp+(line[0:])
            if line.startswith("TIMEWINDOW"):
                qp= qp+ ""+ (line[0:])
                origqp= origqp+(line[0:])
                replaceqp=replaceqp+(line[0:])
               
    qp=qp.split('SELECT')
    qp=qp[1:]
    origqp=origqp.split('SELECT')
    origqp=origqp[1:]
    replaceqp=replaceqp.split('SELECT')
    replaceqp=replaceqp[1:]
    
    PQlabel=dict()
    PQlabels=dict()
    Edits=dict()

    def get_button(t):

    #window for modifying the text descrition of UQ
    # Toplevel object which will
    # be treated as a new window
        M_window = Toplevel(master)
    #Create an instance of tkinter frame or window
    

    #Define the geometry
        M_window.geometry('900x220+10+50')    
        M_window.title( "Modify utility query")

        UQT=Text(M_window, width=80, height=6)
        UQT.pack()
        
        UQT.delete("1.0", "end-1c")
        UQT.insert("end-1c",t)
        

        def modify():
            
            for p,q in PQlabel.items():
                if t==p:                    
                    text1=UQT.get("1.0",END)
                    text1=text1[:-1]
                    text2=q['text']
                    text3=text2.replace(t,text1)                   
                    PQlabel[p].config(text=text3)          
                    

                    with open(resource_path('UQs.txt'),"r+") as f:
                        data=f.read()
                        v1=(t).replace("?",r"\?")
                        p1= (text1).replace("?",r"\?")
                        data = re.sub(v1, p1, data)
                        f.seek(0)
                        f.truncate()
                        f.write(data)

                    #reading UQs in text
                    with open(resource_path('UQs.txt'),"r") as file:
                        
                        uqs = ""
                        sp=""
                        l=""
                        for i,j in enumerate(file):
                            if i>0 and j.startswith("I"):
                                uqs= uqs+(j[0:])
                            if i>0 and j.startswith("UQ"):
                                l= l+(j[0:])                            
                            if i==0:
                               sp= sp+(j[0:])           
                    uqs=uqs.split('\n')
                    l=l.split('\n')

                       
                    #reading UQs in SPARQL
                    with open(resource_path('UQs.sparql'),"r") as fileUQ:
                        
                        UQ = ""
                        for line in fileUQ:
                            if line.startswith("SELECT"):
                                UQ= UQ+(line[0:])
                            if line.startswith("WHERE"):
                                UQ= UQ+ ""+ (line[0:])
                            if line.startswith("GROUP BY"):
                                UQ= UQ+ ""+ (line[0:])
                            if line.startswith("TIMEWINDOW"):
                                UQ= UQ+ ""+ (line[0:])            
                    UQ=UQ.split('SELECT')
                    UQ=UQ[1:]

                    
                    for item in tview.get_children():
                                tview.delete(item)

                    for i,j in enumerate(uqs):
                        for u,v in enumerate(l):
                            if i%2==0:
                                if i==u:
                                    tview.insert(parent='', index='end', iid='123'+str(i), text=(v), values=([uqs[i]]), tags=('even',))
                                    for m,n in enumerate(UQ):
                                        if m==i:
                                            tview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+UQ[i]]))
                            else:
                                if i==u:
                                    tview.insert(parent='', index='end', iid='123'+str(i), text=(v), values=([uqs[i]]), tags=('odd',))
                                    for m,n in enumerate(UQ):              
                                        if m==i:
                                            tview.insert(parent='123'+str(i), index='end', iid='1123'+str(m),text='', values=(['SELECT'+UQ[i]]))
   
                    
                                                       
                    M_window.destroy()
        save_btn = ttk.Button(M_window, text="Save", command=modify)
        save_btn.pack()

        M_window.mainloop()
        
    #code for dsiplaying all the suggestions for negotiation on window    
    optionsL=[]
    class ExpandoText(tk.Text):
        def insert(self, *args, **kwargs):
            result = tk.Text.insert(self, *args, **kwargs)
            self.reset_height()
            return result

        def reset_height(self):
            height = self.tk.call((self._w, "count", "-update", "-displaylines", "1.0", "end"))
            self.configure(height=height)
            
    for i,j in enumerate(head):
            PQsNum=[]       
            tempp = re.findall(r'\d+', j)
            tempp=str(tempp).replace("['","")
            tempp=str(tempp).replace("']","")
            PQsNum.append(tempp)
           
        
            for r, s in enumerate(sugg):
                if r==i:
                    option=s.replace("\n","")
                    option=option[:-1]
                    options=option.split('!')                    
                    for o in options:
                        optionsL.append(o + '(privacy risk for PQ'+PQsNum[0]+').')
                        
    #Print one of the option given below depending on number of queries
    if len(UQNum)==1:                    
        Tlabel=Label(query1_frame, text= "Choose one of the following options to reduce the privacy risk.",font='bold',wraplength=800,width=90,justify=LEFT,anchor="w")
        Tlabel.grid(row=rows, column=0, sticky='w', padx=5, pady=0)
    else:    
        Tlabel=Label(query1_frame, text= "Choose some of the following options to reduce the privacy risks.",font='bold',wraplength=800,width=90,justify=LEFT,anchor="w")
        Tlabel.grid(row=rows, column=0, sticky='w', padx=5, pady=0)
    #display utility queries  
    for t,u in enumerate(UQNum):
        for x,y in enumerate(lp):            
            if u==y:
                Q1label=Label(query_frame, text= "________________________________________________________________________" ,font='bold',fg='darkgrey')
                Q1label.grid(row=rows+1, column=0, sticky='w', padx=5, pady=0)
                Qlabel=Label(query_frame, text= "Options for negotiating the utility query UQ"+u+":", font='bold')
                Qlabel.grid(row=rows+2, column=0, sticky='w', padx=10, pady=0)
                for p,q in enumerate(uqs):            
                    if p==x:             
                        
                        PQlabel[q]=tk.Label(query_frame, text= q ,font=['italic','10'],wraplength=800, width=95, bg='skyblue',justify=LEFT,anchor="w")
                        PQlabel[q].grid(row=rows+3, column=0, sticky='w', padx=10, pady=0)
                        Edits[q] = Button(query_frame, text ="Modify text", width= 10, background='light grey', activebackground='dark grey',cursor='plus',relief='sunken',
                                  command= lambda t= q: get_button(t))                
                        Edits[q].grid(row=rows+3, column=1, padx=0,pady=0,  sticky='w')
    
                for m,n in enumerate(qp):            
                    if m==x:                
                        n=n[:-1]
                        ttext='SELECT'+str(n)
                        PQlabels[m] = ExpandoText(query_frame,width=70, wrap="word")
                        PQlabels[m].grid(row=rows+4, column=0,sticky='nsew',padx=10, pady=0)
                        gui_window1.update_idletasks()
                        PQlabels[m].delete('1.0', 'end')
                        PQlabels[m].insert('1.0', ttext)                    
                   
        #List for saving the suggestions
        PQsList=''
        ListPQ=[]            
        for n, v in enumerate(optionsL):            
            UQN= 'UQ'+str(u)
            if UQN in v:
                v=str(v).partition("for ")[2].partition(".")[0]
                PQsList+=v
                LPQ=PQsList.split(')')                
                LPQ=LPQ[:-1]
                ListPQ.append(LPQ)
        ListPQ=ListPQ[-1]
        ListPQ=sorted(set(ListPQ))
        ListPQ=list(ListPQ)
        
        #Printing the suggestion to refuse to answer the utility queries
        if len(ListPQ)==1:             
                cbsss[u] = tk.Checkbutton(query_frame, text='Refuse to answer this query (privacy risk for '+ListPQ[0]+ ').' , onvalue=True, offvalue=False,cursor='plus', command=deleteUQ)
                cbsss[u].var = BooleanVar(query_frame, value=False)
                cbsss[u]['variable'] = cbsss[u].var
                cbsss[u].grid(column=0, sticky='w', padx=10, pady=2)
        if len(ListPQ)==2:              
                cbsss[u] = tk.Checkbutton(query_frame, text='Refuse to answer this query (privacy risks for '+ListPQ[0]+ ' and ' +ListPQ[1]+').' , onvalue=True, offvalue=False,cursor='plus', command=deleteUQ)
                cbsss[u].var = BooleanVar(query_frame, value=False)
                cbsss[u]['variable'] = cbsss[u].var
                cbsss[u].grid(column=0, sticky='w', padx=10, pady=2)
        #Printing the suggestions for modifying utility queries       
        for name, value in enumerate(optionsL):
            UQN= 'UQ'+str(u)
            
            if UQN in value:
                value=value.replace(UQN, '')
                name=str(UQN)+ " "+ str(name)              
                cbss[name] = tk.Checkbutton(query_frame, text=value, onvalue=True, offvalue=False, cursor='plus', command=modifyUQ)
                cbss[name].var = BooleanVar(query_frame, value=False)
                cbss[name]['variable'] = cbss[name].var
                cbss[name].grid(column=0, sticky='w', padx=10, pady=2)               
                
        rows=rows+15
    Q2label=Label(query_frame, text= "________________________________________________________________________" ,font='bold',fg='darkgrey')
    Q2label.grid(column=0, sticky='w', padx=5, pady=0)

    #button for applying the modifications made to utility queries to list of queries on main window
    ApplyButton= Button(query2_frame, text ="Apply", width= 15, background='light grey', activebackground='dark grey',cursor='plus',relief='sunken', command=Apply)
    ApplyButton.grid(row=0, column=0, padx=10,pady=50,  sticky='w')    
                    
   
   
    gui_window1.mainloop()

#code detect privacy risks and provide explanation
def checkComp():
    
    compatibilityChecking.main()   

    #reading input to b displayed in treeview
    with open(resource_path('output.txt'),"r") as fileComp:
        Comp = ""
        Agg=""
        AggR=""
        AggEx=""
        Fig=""
        for line in fileComp:
            if line.startswith("Privacy risks"):
                Comp= Comp+(line[0:])
            if line.startswith("No privacy"):
                Comp= Comp+(line[0:])
            if line.startswith("Answering the "):
                Agg= Agg+(line[0:])
            
            if line.startswith("-> Answering"):
                AggEx= AggEx+(line[0:])   
            if line.startswith("("):
                AggEx= AggEx+(line[0:])
            if line.startswith("-> Thus"):
                AggEx= AggEx+(line[0:])
            if line.startswith("    {"):
                AggEx= AggEx+(line[0:])
            if line.startswith("-> From"):
                AggEx= AggEx+(line[0:])
            
            if line.startswith("-> As"):
                AggEx= AggEx+(line[0:])
            if line.startswith("    ("):                    
               AggEx= AggEx+(line[0:])
            if line.startswith("Img"):
                Fig= Fig+(line[0:])
        
        Agg=Agg.split('\n')
        Agg.remove('')

        Fig=Fig.split('\n')
        Fig.remove('')


        AggEx=AggEx.split('<')
       
        
        AggExU=[]
        for i,j in enumerate (AggEx):
            if i==0:
                AggExU.append(j)
            if i>0:
                AggExU.append(j[1:])       
            
        Comp=[Comp]
    AggL=[]
    for i,j in enumerate(Agg):
        sAgg=str(Agg[i])            
        if 'not' in sAgg:            
            AggL.append(Agg[i])
    
               
    for i in Fig:
        path= resource_path(i)
        img= (Image.open(path))      
    

    #Resize the Image using resize method
        resized_image= img.resize((400,100), Image.Resampling.LANCZOS)
        new_image= ImageTk.PhotoImage(resized_image)       
    
    treev.tag_configure('green',background='lightgreen',font=['bold', '20'])
    treev.tag_configure('red',background='indianred',font=['bold', '20'])
    treev.tag_configure('lightred1',background='indianred1', font='bold')
    treev.tag_configure('lightred2',background='indianred2',font='bold')
      
    #entering the text in treeview for privacy risk detection and explanation  
    if Comp==(['No privacy risk detected!\n']):         
        treev.insert(parent='', index='end', iid='1a', open=False, text='', values=Comp,tags=('green',))
                
    else:
        if len(Agg)==1:
            treev.insert(parent='', index='end', iid='1b', text='',open=False, values=(["Privacy risk detected!\n"]),tags=('red',))
        else:
            treev.insert(parent='', index='end', iid='1b', text='',open=False, values=Comp,tags=('red',))
        
        btn3 = Button(thirdS1_frame, text ="Negotiate the utility queries to reduce the privacy risks", width= 55, background='light grey', activebackground='dark grey',
                      cursor='plus',relief='sunken', command=OpenWindow)
        btn3.grid(row=0, column=0, padx=1, sticky='w')
        
    if len(Agg)!=0:
        for i,j in enumerate(Agg):
            if i%2==0:
                treev.insert(parent='1b', index='end', iid='1'+str(i),open=False, text='', values=([Agg[i]]),tags=('lightred1',) )
            else:
                treev.insert(parent='1b', index='end', iid='1'+str(i),open=False, text='', values=([Agg[i]]),tags=('lightred2',))
          
            for r,s in enumerate(AggExU):
                if str(s).startswith("-> Answering utility"):
                    if r==i:
                        treev.insert(parent='1'+str(i), index='end', iid='11'+str(r),open=False,text='', values=([AggExU[r]]))
                               
                                    
                else:
                   
                    if r==i:                            
                        treev.insert(parent='1'+str(i), index='end', iid='11'+str(r),text='',open=True, values=([AggExU[r]]))
                        treev.insert(parent='11'+str(r),image=new_image, index='end', iid='111'+'a', open=True, text='', values=(['']))
                        
        messagebox.showinfo("", "Click the small triangle icon to see the detected privacy risks and their explanation.",parent=master)              
           
#button for anayzing privacy risk        
btnM = Button(thirdB_frame, text ="Analyze",width=20, background='light grey', activebackground='dark grey',cursor='plus',relief='sunken',command=checkComp)
btnM.grid(row=0, column=0,sticky='w')

def clear():
    
    for item in treev.get_children():
              treev.delete(item)
    for widget in thirdS_frame.winfo_children():
                widget.destroy()
    for widget in thirdS1_frame.winfo_children():
                widget.destroy()
    
               
              
#button for clearing the treeview that display privacy risks and their explanation
btnM = Button(thirdB_frame, text ="Clear",width=20, background='light grey', activebackground='dark grey',cursor='plus',relief='sunken',command=clear)
btnM.grid(row=0, column=1, padx=958, sticky='w') 
 
# function to open a new window to add query on a button click
def openNewWindow():
     
    # Toplevel object which will be treated as a new window
    gui_window = Toplevel(master)
    #Create an instance of tkinter frame or window    

    #Define the geometry
    gui_width= gui_window.winfo_screenwidth()               
    gui_height= gui_window.winfo_screenheight()               
    gui_window.geometry("%dx%d" % (gui_width, gui_height))      
    gui_window.title("Add Privacy Query")

    main_frame= Frame(gui_window)
    main_frame.pack(fill=BOTH, expand=1)

    my_canvas= Canvas(main_frame)
    
    mx1_scrollbar = ttk.Scrollbar(main_frame, orient=HORIZONTAL, command=my_canvas.xview)
    m1_scrollbar = ttk.Scrollbar(main_frame, orient=VERTICAL, command=my_canvas.yview)
    mx1_scrollbar.pack(side=BOTTOM, fill=X)
    my_canvas.pack(side=LEFT, fill=BOTH, expand=1)
    m1_scrollbar.pack(side=RIGHT, fill=Y)

    m_canvas.configure(xscrollcommand=mx_scrollbar.set, yscrollcommand=m_scrollbar.set)
    m_canvas.bind('<Configure>', lambda e:m_canvas.configure(scrollregion=m_canvas.bbox("all")))
    

    #Create a Scrollbar

    schema_frame=Frame(my_canvas)
    my_canvas.create_window((0,5), window=schema_frame, anchor="nw")

    second_frame=Frame(my_canvas)
    my_canvas.create_window((0,170), window=second_frame, anchor="nw")

    #Constraints frame
    seventh_frame= Frame(my_canvas)
    my_canvas.create_window((500,170), window=seventh_frame, anchor="nw")
    eighth_frame=Frame(my_canvas)
    my_canvas.create_window((1350,170), window=eighth_frame, anchor="nw")
    third_frame= Frame(my_canvas)
    my_canvas.create_window((500,210), window=third_frame, anchor="nw")
    # Output Frame    
    fourth_frame= Frame(my_canvas)
    my_canvas.create_window((1350,210), window=fourth_frame, anchor="nw")
    #Query frame
    fifth_frame= Frame(my_canvas)
    my_canvas.create_window((10,670), window=fifth_frame, anchor="nw")
    #button frames
    sixth_frame= Frame(my_canvas)
    my_canvas.create_window((0,930), window=sixth_frame, anchor="nw")
    #Apply button frame
    

    #lists and dict for storing the dynamic other data type properties and result variables
    listB=[]
    listP=[]
    listTS=[]
    list_Int=[]
    fil=dict()
    ts=dict()
    cbs = dict()
    res=dict()
    addc=dict()
  
    #reading the schema for loading properties on window
    global R
    R='' 
    
    R= resource_path('issda_schema.ttl')
    g = Graph()
    g.parse(R, format='ttl')

    query1 = """

    SELECT ?a
    WHERE {?a a owl:ObjectProperty
        }
    """

    qres = g.query(query1)


    query2 = """

    SELECT ?a
    WHERE {?a a owl:DynamicProperty
        }
    """

    qresult = g.query(query2)

    query3 = """

    SELECT ?a
    WHERE {?a a owl:DatatypeProperty
        }
    """     

    qresultDT = g.query(query3)
    
    
    def update_text():
        global P_GP
        P_GP = ''
        global GP
        GP=''
        Triple = ''
        global T_GP
        T_GP = ''
        listdr=[]        
        global list_I
        global list_TS
        global list_Result
        global uri
    
    
        for name, checkbutton in cbs.items():
            if checkbutton.var.get():
                query4 = "SELECT  ?c ?d WHERE {"+checkbutton['text']+" rdfs:domain ?c . "+checkbutton['text']+" rdfs:range ?d}"                    
                qres1 = g.query(query4)        
                for row in qres1:
                    domain_range= str(row)
                    list_DR=re.findall(r'\#(.*?)\'', domain_range)
                    for string in list_DR:
                        if string=="integer":
                            Nstring=string.replace("integer", checkbutton['text'])                            
                            Nstring=Nstring.replace(uri, "")
                            list_DR.remove('integer')                                
                            list_DR.append(Nstring)                                
                            list_Int.append(Nstring)
                        if string=="string":
                            Nstring=string.replace("string", checkbutton['text'])
                            Nstring=Nstring.replace(uri, '')                                
                            list_DR.remove('string')
                            list_DR.append(Nstring)
				                         
                        if string=="boolean":
                            Nstring=string.replace("boolean", checkbutton['text'])
                            Nstring=Nstring.replace(uri, '')
                            list_DR.remove('boolean')                                
                            list_DR.append(Nstring)
           
                                                    
                    list_I=set(list_Int)
                    list_I=list(list_I)
                    listdr=list_DR+listdr
                        
                    for i,j in enumerate(listTS):                            
                        if j == checkbutton['text']: 
                            Triple += "(?"+listdr[0] +"  "+checkbutton['text'] + " ?"+(listdr[1]).replace(uri,'') + ", ?timestamp) . "
                        else:
                            Triple += "?"+listdr[0] +"  "+checkbutton['text'] + " ?"+listdr[1] + " . "
                           
                    global list_Result
                    list_Result=(set(listdr))
                    list_Result=list(list_Result)
                       
        #list for domain and range of ObjectProperties        
        global count_list
        count_list = []
        for i in list_Result:
            if i not in list_I:
                count_list.append(i)
                                  
        l=len(Triple)                   
        Remove_last = Triple[:l-3]            
        P_GP += "WHERE {" +Remove_last+ "}"
        GP = "WHERE {" +Remove_last+ "}"
        T_GP = "WHERE {" +Remove_last       
                
                
        for widget in fourth_frame.winfo_children():
            widget.destroy()
                    
        for widget in third_frame.winfo_children():
            widget.destroy()
          
        if len(P_GP) > 10:
            text.delete('1.0', 'end')
            text.insert('1.0', P_GP)
            
            global r           
            r=3
            def pick_type(e):
                global F1
                F1=True    
                query_cons = "SELECT  ?a WHERE {?a rdfs:subClassOf "+uri+con_dropdown.get()+"}"                    
                qres_cons = g.query(query_cons)
                list_constraint=[]
                for row in qres_cons:
                    constraint_type= str(row)
                    list_cons=re.findall(r'\#(.*?)\'', constraint_type)
                    list_constraint.append(list_cons)
                    
                query_pro = "SELECT  ?a WHERE {"+uri+con_dropdown.get()+" rdfs:subPropertyOf ?a}"                    
                qres_pro = g.query(query_pro)
                list_property=[]
                for row in qres_pro:
                    property_type= str(row)
                    list_pro=re.findall(r'\#(.*?)\'', property_type)
                    list_property.append(list_pro)
                if len(list_constraint)!=0:
                    cons_val= [
                    "FILTER",
                    "rdf:type"
                    ]
                if len(list_property)!=0:                       
                    cons_val= [
                    "FILTER",
                    "rdfs:subPropertyOf"
                    ]
                if len(list_property)==0 and len(list_constraint)==0: 
                    cons_val= [
                    "FILTER"                            
                    ]
                #code for adding constraints    
                def pick_constraint(e):
                                                                
                    def update_filter(e):                        
                        global P_GP
                        global GP
                        global FilterC
                        FilterC=""

                        def update_filter1(e):    
                            global r
                            global cons_dropdown
                            global con_dropdown
                            global fil_dropdown1
                            global entry1
                            global P_GP
                            global GP
                            global FilterC                            
                            
                            if cons_dropdown.get()=="FILTER" and entry1.get()!='':
                                FilterC=""
                                FilterC += " . " + cons_dropdown.get() + "( ?"+con_dropdown.get() + " "+ fil_dropdown1.get()+ " "+ entry1.get()
                                P_GP=  T_GP + FilterC + " )} "
                                GP = T_GP + FilterC + " )} "
                                text.delete('1.0', 'end')
                                text.insert('1.0', P_GP)
                                
                        def add_constraint(e):
                            global r
                            global cons_dropdown
                            global con_dropdown
                            global fil_dropdown1
                            global entry1
                            global P_GP
                            global GP
                            global FilterC                                           
                                
                            def Apick_type(e):
                                global F2
                                F2=True
                                global r
                                query_cons = "SELECT  ?a WHERE {?a rdfs:subClassOf "+uri+Acon_dropdown.get()+"}"                    
                                qres_cons = g.query(query_cons)
                                Alist_constraint=[]
                                for row in qres_cons:
                                    constraint_type= str(row)
                                    list_cons=re.findall(r'\#(.*?)\'', constraint_type)
                                    Alist_constraint.append(list_cons)                                    
                                query_pro = "SELECT  ?a WHERE {"+uri+Acon_dropdown.get()+" rdfs:subPropertyOf ?a}"                    
                                qres_pro = g.query(query_pro)
                                Alist_property=[]
                                for row in qres_pro:
                                    property_type= str(row)
                                    list_pro=re.findall(r'\#(.*?)\'', property_type)
                                    Alist_property.append(list_pro)

                                if len(Alist_constraint)!=0:
                                    Acons_val= [
                                    "FILTER",
                                    "rdf:type"
                                    ]
                                if len(Alist_property)!=0:                       
                                    Acons_val= [
                                    "FILTER",
                                    "rdfs:subPropertyOf"
                                    ]
                                if len(Alist_property)==0 and len(Alist_constraint)==0: 
                                     Acons_val= [
                                    "FILTER"                            
                                    ]
                                def Apick_constraint(e):
                                    global r
                                    global Afil_dropdown1
                                    global Aentry1

                                                                                               
                                    def update_filter2(e):
                                        def update_consf(e):
                                            global F2
                                            F2=True
                                            global Acons_dropdown
                                            global Acon_dropdown
                                            global Afil_dropdown1
                                            global cons_dropdown
                                            global con_dropdown
                                            global fil_dropdown1
                                            global entry1
                                            global P_GP
                                            global GP                            
                                            global FilterC                                           
                                                                                        
                                            
                                            if (cons_dropdown.get()=="FILTER") and (cons_dropdown.get()==Acons_dropdown.get()):
                                                FilterC += " && " +"?"+Acon_dropdown.get() + " "+ Afil_dropdown1.get()+ " "+ Aentry1.get()
                                                if entry1.get()!='' and Aentry1.get()!='':
                                                    P_GP=  T_GP + FilterC + " )} "
                                                    GP = T_GP + FilterC + " )} "
                                                    text.delete('1.0', 'end')
                                                    text.insert('1.0', P_GP)                                     
                                                                    
                                            if (cons_dropdown.get()!="FILTER") and (Acons_dropdown.get()=="FILTER"):
                                                FilterC += " . " + Acons_dropdown.get() + "( ?"+Acon_dropdown.get() + " "+ Afil_dropdown1.get()+ " "+ Aentry1.get() 
                                                if Aentry1.get()!='':
                                                    P_GP=  T_GP + FilterC+ " )} "
                                                    GP = T_GP + FilterC+ " )} "
                                                    text.delete('1.0', 'end')
                                                    text.insert('1.0', P_GP)
                                                                                                                                
                                        constraint= Button(third_frame, text='Another Constraint')
                                        constraint.grid(column=0,row=20,sticky='w', pady=2)
                                        for b in [constraint]:
                                            b.bind("<Button>", update_consf)
                                            b.bind("<ButtonRelease>", add_constraint)                                                                         

                                    def update_cons(e):
                                        global F2
                                        F2=True
                                        global cons_dropdown
                                        global con_dropdown
                                        global fil_dropdown1
                                        global entry1
                                        global P_GP
                                        global GP                            
                                        global FilterC
                                                                                
                                        if (cons_dropdown.get()=="FILTER") and (Acons_dropdown.get()!="FILTER"):
                                            FilterC = " . ?"+Acon_dropdown.get() + " "+ Acons_dropdown.get() +" "+ uri+ Afil_dropdown1.get() + FilterC 
                                            if entry1.get()!='':
                                                P_GP=  T_GP + FilterC+ " )} "
                                                GP = T_GP + FilterC+ " )} "
                                                text.delete('1.0', 'end')
                                                text.insert('1.0', P_GP)                                                                              
                                        
                                        if (cons_dropdown.get()=="rdf:type") or (cons_dropdown.get()=="rdfs:subPropertyOf") and (Acons_dropdown.get()!= "FILTER"):
                                            FilterC = " . ?"+Acon_dropdown.get() + " "+ Acons_dropdown.get() +" "+ uri+ Afil_dropdown1.get() + FilterC
                                            P_GP=  T_GP + FilterC+ "} "
                                            GP = T_GP + FilterC+ "} "
                                            text.delete('1.0', 'end')
                                            text.insert('1.0', P_GP)

                                        constraint= Button(third_frame, text='Another Constraint')
                                        constraint.grid(column=0,row=20,sticky='w', pady=2)
                                        for b in [constraint]:
                                            b.bind("<Button>", add_constraint)
                    
                                                                                            
                                    if Acons_dropdown.get()=="FILTER":
                                        Filter = [
                                        "=",
                                        ">",
                                        "<",
                                        ">=",
                                        "<="
                                            ]
                                        Afil_dropdown1= ttk.Combobox(third_frame, textvariable='',value=Filter)
                                        Afil_dropdown1.grid(column=2, row=r,sticky='w', pady=2)                                         
                                        Afil_dropdown1.current(0)                                        
                                        Aentry1= Entry(third_frame, width=20, textvariable='')
                                        Aentry1.grid(column=3, row=r,sticky='w', pady=2)
                                        r=r+1
                                        Afil_dropdown1.bind("<<ComboboxSelected>>", update_filter2)
                                    
                                    if Acons_dropdown.get()=="rdf:type":                            
                                        Afil_dropdown1= ttk.Combobox(third_frame, textvariable='',value=Alist_constraint)
                                        Afil_dropdown1.grid(column=2, row=r,sticky='w', pady=2)
                                        r=r+1 
                                        Afil_dropdown1.current(0)
                                        Afil_dropdown1.bind("<<ComboboxSelected>>", update_cons)
                                     
                                    if Acons_dropdown.get()=="rdfs:subPropertyOf":
                                        Afil_dropdown1= ttk.Combobox(third_frame, textvariable='',value=Alist_property)
                                        Afil_dropdown1.grid(column=2, row=r,sticky='w', pady=2)
                                        r=r+1 
                                        Afil_dropdown1.current(0)
                                        Afil_dropdown1.bind("<<ComboboxSelected>>", update_cons)
                                        
                                global Acons_dropdown
                                global Afil_dropdown1
                                global Aentry1
                                Acons_dropdown= ttk.Combobox(third_frame, textvariable='',value=Acons_val)
                                Acons_dropdown.grid(column=1, row=r,sticky='w', pady=2)
                                Acons_dropdown.current(0)
                                Acons_dropdown.bind("<<ComboboxSelected>>", Apick_constraint)

                            for i,val in enumerate(listTS):                    
                                for s,t in enumerate(list_Result):
                                    global Acon_dropdown
                                    val=val.replace(uri,'')
                                    if (t==val):
                                        Acon_dropdown= ttk.Combobox(third_frame, textvariable='',value=list_Result)
                                        Acon_dropdown.grid(column=0, row=r,sticky='w', pady=2)
                                        Acon_dropdown.current(0)
                                        Acon_dropdown.bind("<<ComboboxSelected>>", Apick_type)
                                    else:
                                        Acon_dropdown= ttk.Combobox(third_frame, textvariable='',value=list_Result)
                                        Acon_dropdown.grid(column=0, row=r,sticky='w', pady=2)
                                        Acon_dropdown.current(0)
                                        Acon_dropdown.bind("<<ComboboxSelected>>", Apick_type)   
                        

                        constraint= Button(third_frame, text='Another Constraint')                                              
                        constraint.grid(column=0,row=20,sticky='w', pady=2)
                            
                        for b in [constraint]:
                            b.bind("<Button>", update_filter1)
                            b.bind("<ButtonRelease>", add_constraint)
                            
                        
                        if (fil_dropdown1.get() and cons_dropdown.get()=="rdf:type") or (fil_dropdown1.get()and cons_dropdown.get()=="rdfs:subPropertyOf"):
                            FilterC=""
                            FilterC += " . ?"+con_dropdown.get() + " "+ cons_dropdown.get() + " "+uri+ fil_dropdown1.get()
                            P_GP=  T_GP + FilterC+ "} "
                            GP = T_GP + FilterC+ "} "
                            text.delete('1.0', 'end')
                            text.insert('1.0', P_GP)      
                        

                    global fil_dropdown1
                    global entry1
                    if cons_dropdown.get()=="FILTER":
                        Filter = [
                        "=",
                        ">",
                        "<",
                        ">=",
                        "<="
                            ]
                        fil_dropdown1= ttk.Combobox(third_frame, textvariable='',value=Filter)
                        fil_dropdown1.grid(column=2, row=1,sticky='w', pady=2)
                        fil_dropdown1.current(0)
                        fil_dropdown1.bind("<<ComboboxSelected>>", update_filter)                        
                        entry1= Entry(third_frame, width=20, textvariable='')
                        entry1.grid(column=3, row=1,sticky='w', pady=2)
                    if cons_dropdown.get()=="rdf:type":                            
                        fil_dropdown1= ttk.Combobox(third_frame, textvariable='',value=list_constraint)
                        fil_dropdown1.grid(column=2, row=1,sticky='w', pady=2)
                        fil_dropdown1.current(0)
                        fil_dropdown1.bind("<<ComboboxSelected>>", update_filter)
                    if cons_dropdown.get()=="rdfs:subPropertyOf":
                        fil_dropdown1= ttk.Combobox(third_frame, textvariable='',value=list_property)
                        fil_dropdown1.grid(column=2, row=1,sticky='w', pady=2)
                        fil_dropdown1.current(0)
                        fil_dropdown1.bind("<<ComboboxSelected>>", update_filter)                    
                    

                global cons_dropdown    
                cons_dropdown= ttk.Combobox(third_frame, textvariable='',value=cons_val)
                cons_dropdown.grid(column=1, row=1,sticky='w', pady=2)
                cons_dropdown.current(0)
                cons_dropdown.bind("<<ComboboxSelected>>", pick_constraint)                     
                    
                 
            for i,val in enumerate(listTS):
                global con_dropdown
                for s,t in enumerate(list_Result):
                    val=val.replace(uri,'')
                    if (t==val):
                        list_Result.append('timestamp')
                        list_Res=list_Result
                        con_dropdown= ttk.Combobox(third_frame, textvariable='',value=list_Result)
                        con_dropdown.grid(column=0, row=1,sticky='w', pady=2)
                        con_dropdown.current(0)
                        con_dropdown.bind("<<ComboboxSelected>>", pick_type)
                            
                    else:
                        con_dropdown= ttk.Combobox(third_frame, textvariable='',value=list_Result)
                        con_dropdown.grid(column=0, row=1,sticky='w', pady=2)
                        con_dropdown.current(0)
                        con_dropdown.bind("<<ComboboxSelected>>", pick_type)
            #adding constraints in query formuation            
            def update_result():
                global F1
                global F2
                global P_GP
                global GP                                         
                global Results
                global FilterC
                
                Results=''
                if F2==False:
                    if F1==True:           
                        if cons_dropdown.get()=="FILTER" and entry1.get()!='':
                            FilterC=''
                            FilterC += " . " + cons_dropdown.get() + "( ?"+con_dropdown.get() + " "+ fil_dropdown1.get()+ " "+ entry1.get()
                            P_GP=  T_GP + FilterC + " )} "
                            GP = T_GP + FilterC + " )} "
                            text.delete('1.0', 'end')
                            text.insert('1.0', P_GP)
                    else:
                        pass
                else:
                    pass
                
                if F2==True:
                    if (cons_dropdown.get()=="FILTER") and (cons_dropdown.get()==Acons_dropdown.get()):
                        FilterC += " && " +"?"+Acon_dropdown.get() + " "+ Afil_dropdown1.get()+ " "+ Aentry1.get()
                        if entry1.get()!='' and Aentry1.get()!='':
                            P_GP=  T_GP + FilterC + " )} "
                            GP = T_GP + FilterC + " )} "
                            text.delete('1.0', 'end')
                            text.insert('1.0', P_GP)
                else:
                    pass
             
                if F2==True:
                    if (cons_dropdown.get()!="FILTER") and (Acons_dropdown.get()=="FILTER"):
                        FilterC += " . " + Acons_dropdown.get() + "( ?"+Acon_dropdown.get() + " "+ Afil_dropdown1.get()+ " "+ Aentry1.get() 
                        if Aentry1.get()!='':
                            P_GP=  T_GP + FilterC+ " )} "
                            GP = T_GP + FilterC+ " )} "
                            text.delete('1.0', 'end')
                            text.insert('1.0', P_GP)
                else:
                    pass
                                                            
                for name, checkbutton in res.items():
                    if checkbutton.var.get():
                        Results += "?"+checkbutton['text']+ ' '      
                        if len(Results)>3:
                            P_GP= "SELECT "+Results+ '\n' + GP     
                            text.delete('1.0', 'end')
                            text.insert('1.0',P_GP )
                    
                        #save privacy query for analyzing privacy risk and also display at user interface
           
                        def save_PQ():                            
                            if (len(textW.get('1.0', 'end')) >= 2):
                                with open(resource_path('PQs.txt'),"a+") as file:                                  
                                    file.write('\n'+textW.get(1.0, END))                                 
                                    file.close
                                with open(resource_path('PQs.sparql'),"a+") as fPQ:                                   
                                    fPQ.write('\n'+text.get(1.0, END))                                    
                                    fPQ.close                                  
                
                                for item in tv.get_children():
                                    tv.delete(item)            

                                #reading PQs in SPARQL
                                with open(resource_path('PQs.sparql'),"r") as file:           
                                    q = ""
                                    for line in file:                                    
                                        if line.startswith("SELECT"):
                                            q= q+(line[0:])
                                        if line.startswith("WHERE"):
                                            q= q+ ""+ (line[0:])
                                        if line.startswith("GROUP BY"):
                                            q= q+ ""+ (line[0:])
                                        if line.startswith("TIMEWINDOW"):
                                            q= q+ ""+ (line[0:])            
                                q=q.split('SELECT')
                                q=q[1:]
                                #reading PQs in text
                                pqs=''
                                with open(resource_path('PQs.txt'),"r") as file:
                                    
                                    for line in file:            
                                        if line=='\n':
                                            line.strip('\n')
                                        else:
                                            pqs=pqs+(line[0:])
                                pqs=pqs.split('\n')
                                pqs=pqs[:-1]
                                     
                                for i,j in enumerate(pqs):
                                    if i%2==0:
                                        tv.insert(parent='', index='end', iid='12'+str(i), text=('PQ'+str(i+1)), values=([pqs[i]]), tags=('evenrow',))
                                        for m,n in enumerate(q):
                                            if m==i:
                                                tv.insert(parent='12'+str(i), index='end', iid='112'+str(m),text='', values=(['SELECT'+q[i]]))
                                    else:
                                        tv.insert(parent='', index='end', iid='12'+str(i), text=('PQ'+str(i+1)), values=([pqs[i]]), tags=('oddrow',))
                                        for m,n in enumerate(q):
                                            if m==i:
                                                tv.insert(parent='12'+str(i), index='end', iid='112'+str(m),text='', values=(['SELECT'+q[i]]))  
                                messagebox.showinfo("", "Privacy query added.",parent=gui_window)
                            else:
                                messagebox.showerror("Error", "Enter privacy query in words.",parent=gui_window)                             
        
                        savePQ_button= Button(fifth_frame, text='Save Query',font='bold', width=10, background='light grey', activebackground='dark grey',cursor='plus', relief='sunken', command=save_PQ)
                        savePQ_button.grid(row=2, column=0, sticky='e',padx=20, pady=10)
                                                  
            global Results
            Results=''
            #removing timestamp
            for i, value in enumerate(list_Result):
                if value==('timestamp'):
                    list_Result.remove('timestamp')
            #displaying output variables
            for i, value in enumerate(list_Result):                    
                res[value] = Checkbutton(fourth_frame, text=value, onvalue=True, offvalue=False, cursor='plus', command=update_result)
                res[value].var = BooleanVar(fourth_frame, value=False)
                res[value]['variable'] = res[value].var
                res[value].grid(column=0, sticky='w', pady=2)
            #adding output varaiables to query    
            def clicked():
                if var.get():            
                    def pick_function(e):
                        if my_dropdown.get()=="COUNT":
                            agg_dropdown.config(value=list_Result)
                            agg_dropdown.current(0)           
                        else:
                            agg_dropdown.config(value=list_I)
                            agg_dropdown.current(0)
                    def time_window(e):
                        global P_GP
                        global GP
                                   
                        if len(Results)> 3 and var.get() and my_dropdown.get(): 
                            P_GP= "SELECT "+Results+ my_dropdown.get()+"(?"+ agg_dropdown.get()+")" + '\n' + GP + '\n' + "GROUP BY " + Results    
                            text.delete('1.0', 'end')
                            text.insert('1.0',P_GP )
                                                
                        if len(Results)< 3 and var.get()and my_dropdown.get():
                            P_GP= "SELECT "+Results+ my_dropdown.get()+"(?"+ agg_dropdown.get()+")" + '\n' + GP + '\n'   
                            text.delete('1.0', 'end')
                            text.insert('1.0',P_GP )

                        #save privacy query for analyzing privacy risk and also display at user interface
                        def save_PQ():
                            if (len(textW.get('1.0', 'end')) >= 2):
                                with open(resource_path('PQs.txt'),"a+") as file:                                 
                                    file.write('\n'+textW.get(1.0, END))                                    
                                    file.close
                                with open(resource_path('PQs.sparql'),"a+") as fPQ:                                    
                                    fPQ.write('\n'+text.get(1.0, END))                                  
                                    fPQ.close                
                                for item in tv.get_children():
                                    tv.delete(item)            

                                #reading PQs in SPARQL
                                with open(resource_path('PQs.sparql'),"r") as file:           
                                    q = ""
                                    for line in file:
                                        
                                        if line.startswith("SELECT"):
                                            q= q+(line[0:])
                                        if line.startswith("WHERE"):
                                            q= q+ ""+ (line[0:])
                                        if line.startswith("GROUP BY"):
                                            q= q+ ""+ (line[0:])
                                        if line.startswith("TIMEWINDOW"):
                                            q= q+ ""+ (line[0:])            
                                q=q.split('SELECT')
                                q=q[1:]
                                #reading PQs in text
                                pqs=''
                                with open(resource_path('PQs.txt'),"r") as file:
                                    
                                    for line in file:            
                                        if line=='\n':
                                            line.strip('\n')
                                        else:
                                            pqs=pqs+(line[0:])
                                pqs=pqs.split('\n')
                                pqs=pqs[:-1]
                              
                                for i,j in enumerate(pqs):
                                    if i%2==0:
                                        tv.insert(parent='', index='end', iid='12'+str(i), text=('PQ'+str(i+1)), values=([pqs[i]]), tags=('evenrow',))
                                        for m,n in enumerate(q):
                                            if m==i:
                                                tv.insert(parent='12'+str(i), index='end', iid='112'+str(m),text='', values=(['SELECT'+q[i]]))
                                    else:
                                        tv.insert(parent='', index='end', iid='12'+str(i), text=('PQ'+str(i+1)), values=([pqs[i]]), tags=('oddrow',))
                                        for m,n in enumerate(q):
                                            if m==i:
                                                tv.insert(parent='12'+str(i), index='end', iid='112'+str(m),text='', values=(['SELECT'+q[i]]))  
                                messagebox.showinfo("", "Privacy query added.",parent=gui_window)
                            else:
                                messagebox.showerror("Error", "Enter privacy query in words.",parent=gui_window)

                        savePQ_button= Button(fifth_frame, text='Save Query',font='bold', width=10, background='light grey', activebackground='dark grey',cursor='plus', relief='sunken', command=save_PQ)
                        savePQ_button.grid(row=2, column=0, sticky='e',padx=20, pady=10)
                                
                        # time window input widgets
                        for i,val in enumerate(listTS):
                            val=val.replace(uri,'')
                            if (agg_dropdown.get()==val):
                                size_label= Label(fourth_frame, text='Time window size:')
                                size_label.grid(row=18,column=0, sticky='w', pady=2)
                
                                size_entry= Entry(fourth_frame, width=5)
                                size_entry.grid(row=18,column=1, sticky='w', pady=2)

                                Time = [
                                "h",
                                "m",
                                "s"                    
                                ]
                                TSize_dropdown = StringVar()
                                TSize_dropdown= ttk.Combobox(fourth_frame, textvariable='',value=Time, width=5)
                                TSize_dropdown.grid(row=18, column=2, sticky='w', pady=2)
                                TSize_dropdown.current(0)                    

                                step_label= Label(fourth_frame, text='Time window step:')
                                step_label.grid(row=19, column=0, sticky='w', pady=2)

                                step_entry= Entry(fourth_frame, width=5)
                                step_entry.grid(row=19,column=1, sticky='w', pady=2)
                                
                                #displaying time windows in query that is constructed
                                def save_TW(e):
                                    if var.get() and size_entry.get()!='' and step_entry.get()!= '':
                                        P_GP= "SELECT "+Results+ "?timeWindowEnd " + my_dropdown.get()+"(?"+ agg_dropdown.get()+")" + '\n' + GP + '\n' + "GROUP BY " + Results + "?timeWindowEnd "+'\n' + "TIMEWINDOW ("+size_entry.get()+TSize_dropdown.get()+ ", " +step_entry.get()+TStep_dropdown.get()+")"    
                                        text.delete('1.0', 'end')
                                        text.insert('1.0',P_GP )                 
                                        def save_PQ():
                                            if (len(textW.get('1.0', 'end')) >= 2):
                                                with open(resource_path('PQs.txt'),"a+") as file:
                                                    
                                                    file.write('\n'+textW.get(1.0, END))
                                                    
                                                    file.close
                                                with open(resource_path('PQs.sparql'),"a+") as fPQ:
                                                  
                                                    fPQ.write('\n'+text.get(1.0, END))
                                                    
                                                    fPQ.close
                
                                                for item in tv.get_children():
                                                    tv.delete(item)            

                                                #reading PQs in SPARQL
                                                with open(resource_path('PQs.sparql'),"r") as file:           
                                                    q = ""
                                                    for line in file:
                                                        
                                                        if line.startswith("SELECT"):
                                                            q= q+(line[0:])
                                                        if line.startswith("WHERE"):
                                                            q= q+ ""+ (line[0:])
                                                        if line.startswith("GROUP BY"):
                                                            q= q+ ""+ (line[0:])
                                                        if line.startswith("TIMEWINDOW"):
                                                            q= q+ ""+ (line[0:])            
                                                q=q.split('SELECT')
                                                q=q[1:]
                                                #reading PQs in text
                                                pqs=''
                                                with open(resource_path('PQs.txt'),"r") as file:
                                                    
                                                    for line in file:            
                                                        if line=='\n':
                                                            line.strip('\n')
                                                        else:
                                                            pqs=pqs+(line[0:])
                                                pqs=pqs.split('\n')
                                                pqs=pqs[:-1]
                                                
                                                for i,j in enumerate(pqs):
                                                    if i%2==0:
                                                        tv.insert(parent='', index='end', iid='12'+str(i), text=('PQ'+str(i+1)), values=([pqs[i]]), tags=('evenrow',))
                                                        for m,n in enumerate(q):
                                                            if m==i:
                                                                tv.insert(parent='12'+str(i), index='end', iid='112'+str(m),text='', values=(['SELECT'+q[i]]))
                                                    else:
                                                        tv.insert(parent='', index='end', iid='12'+str(i), text=('PQ'+str(i+1)), values=([pqs[i]]), tags=('oddrow',))
                                                        for m,n in enumerate(q):
                                                            if m==i:
                                                                tv.insert(parent='12'+str(i), index='end', iid='112'+str(m),text='', values=(['SELECT'+q[i]]))  
                                                messagebox.showinfo("", "Privacy query added.",parent=gui_window)
                                                gui_window.destroy()
                                            else:
                                                messagebox.showerror("Error", "Enter privacy query in words.",parent=gui_window)
                            
                                                
                                        savePQ_button= Button(fifth_frame, text='Save Query',font='bold', width=10, background='light grey', activebackground='dark grey',cursor='plus', relief='sunken', command=save_PQ)
                                        savePQ_button.grid(row=2, column=0, sticky='e',padx=20, pady=10)
                                       
                                #widgets to provide the input for time windows     
                                Time = [
                                    "h",
                                    "m",
                                    "s"                    
                                    ]
                                TStep_dropdown = StringVar()
                                TStep_dropdown= ttk.Combobox(fourth_frame, textvariable='',value=Time, width=5)
                                TStep_dropdown.grid(row=19, column=2, sticky='w', pady=2)
                                TStep_dropdown.current(0)
                                TStep_dropdown.bind("<<ComboboxSelected>>", save_TW)
                        
                    #widgets to provide input for aggregate
                    Aggregate=[
                    "SUM",
                    "COUNT",
                    "MIN",
                    "MAX"]
                    my_dropdown= ttk.Combobox(fourth_frame, value=Aggregate, width=12)
                    my_dropdown.current(0)
                    my_dropdown.grid(row=15,column=0,sticky='w', pady=2)
                    my_dropdown.bind("<<ComboboxSelected>>", pick_function)
    
                    On=Label(fourth_frame, text='on', width=2, anchor='center')
                    On.grid(row=15, column=1, sticky='ew',pady=2)

                    agg_dropdown= ttk.Combobox(fourth_frame, value=[""], width=18)
                    agg_dropdown.current(0)
                    agg_dropdown.grid(row=15, column=2,sticky='w', pady=2)
                    agg_dropdown.bind("<<ComboboxSelected>>", time_window)            
                
            var = BooleanVar() 
            var.set(False)
            Aggregate1=Checkbutton(fourth_frame, text='Aggregate', variable=var, onvalue=True, offvalue=False, cursor='plus',anchor='w',command=clicked)
            Aggregate1.grid(column=0, sticky='w', pady=5)
        else:
            text.delete('1.0', 'end')                            
            
            for widget in third_frame.winfo_children():
                widget.destroy()
            for widget in fourth_frame.winfo_children():
                widget.destroy()               
    global F1
    global F2
    global uri
    F1=False
    F2=False
    #reading the properties from schema
    for row in qres:        
        pro= str(row)
        properties=pro.split("#", 1)[1].split("'", 1)[0]
        uri=pro.rsplit("/", 1)[1].split("#", 1)[0]
        uri=uri+":"
        listB.append(uri+properties)                   
        
    for row in qresult:        
        Dpro= str(row)       
        Dproperties=Dpro.split("#", 1)[1].split("'", 1)[0]
        listB.append(uri+Dproperties)        
        listTS.append(uri+Dproperties)
       
    for row in qresultDT:        
        Dynamicpro= str(row)
        properties=Dynamicpro.split("#", 1)[1].split("'", 1)[0]
        listB.append(uri+properties)   
       
    #create frame to display properties
    textS = ScrolledText(second_frame, width=30,height=22)
    textS.grid(row=1, column=0, padx=10, pady=5)

    #display the properties in frame
    for i, value in enumerate(listB):
        cbs[value] = tk.Checkbutton(textS, text=value, onvalue=True, offvalue=False,cursor='plus',anchor='w',bg='white', command=update_text)
        cbs[value].var = BooleanVar(second_frame, value=False)
        cbs[value]['variable'] = cbs[value].var
        cbs[value].grid(column=0, sticky='w', pady=2)
        textS.window_create('end', window=cbs[value])
        textS.insert('end', '\n')
        
    #text to appear on query building window  
    Query1= Label(schema_frame, text='Privacy query in words:',font='bold')
    Query1.grid(row=0, column=0, sticky='w',padx=10, pady=5)                    
    textW = Text(schema_frame,width=80,height=5)
    textW.grid(row=1, column=0,sticky='w',padx=10, pady=5)
    Query= Label(fifth_frame, text='Privacy query building in query language:',font='bold')
    Query.grid(row=0, column=0, sticky='w',pady=5)                    
    text = Text(fifth_frame,width=80,height=10)
    text.grid(row=1, column=0,sticky='w',pady=5)
    button=Label(second_frame, text='Properties:',font='bold')
    button.grid(row=0, column=0, sticky='w', padx=10, pady=5)
    FilterL=Label(seventh_frame, text='Constraints:',font='bold')
    FilterL.grid(row=0, column=0, sticky='w', pady=5)
    OutputL=Label(eighth_frame, text='Output:',font='bold')
    OutputL.grid(row=0, column=0, sticky='w', pady=5)
    
    # reset the window defined for query construction
    def restart():
        gui_window.destroy()
        openNewWindow()

    Reset_button= Button(fifth_frame, text='Reset',font='bold', width=10, background='light grey', activebackground='dark grey',cursor='plus', relief='sunken',command=restart)
    Reset_button.grid(row=2, column=0, sticky='w', padx=20, pady=10)
                  
    gui_window.mainloop() 
 
# a button widget which will open a new window to build query 
btn = Button(treeB_frame, text ="Add privacy query",width=20, background='light grey', activebackground='dark grey',cursor='plus',relief='sunken', command = openNewWindow)
btn.grid(row=0, column=0, sticky='w')


master.mainloop()
