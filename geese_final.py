#!/usr/bin python
__author__ = 'Julia Noce'

#-*- coding:utf-8 -*-
from Tkinter import *
from ttk import *
from scapy.all import *
import time
from threading import Thread,Event


class Pacote:
    def __init__(self):

        self.n = int(main.sqNumEntry.get())
        self.q = int(main.razaoEntry.get())
        self.a1 = int(main.minTimeEntry.get())
        self.an = int (self.a1 * (self.q **(self.n-1)))
        self.maxtime = int(main.maxTimeEntry.get())
        self.stnumIni = 0
        self.stnum = int(main.stNumEntry.get())
        self.sqnum = int(main.sqNumEntry.get())


        self.appid = int(main.AppIDEntry.get())
        self.macsource = main.MACSourceEntry.get()
        self.macdst = main.MACaddressEntry.get()
        self.ethernet = Ether(dst= self.macdst,src= self.macsource)

        self.prio = Dot1Q(prio= int(main.variable.get()), id= int(0), vlan= 1)
        self.prio.fields_desc[3]=XShortEnumField("type",0x88b8,ETHER_TYPES)



        self.tag0 = "61".decode("hex")
        self.tag1 = "80".decode("hex")
        self.tag2 = "81".decode("hex")
        self.tag3 = "82".decode("hex")
        self.tag4 = "83".decode("hex")
        self.tag5 = "84".decode("hex")
        self.tag6 = "85".decode("hex")
        self.tag7 = "86".decode("hex")
        self.tag8 = "87".decode("hex")
        self.tag9 = "88".decode("hex")
        self.tag10 = "89".decode("hex")
        self.tag11 = "8a".decode("hex")
        self.tag12 = "ab".decode("hex")

        self.gocbref = str([x[1] for x in main.dataDefault]).replace("['", "").replace("']", "") + '/LLN0$GO$Goose' + str([x[0] for x in main.dataDefault]).replace("['", "").replace("']", "")
        self.timeallow = ('0' + str(hex(int(main.timeAllowEntry.get()))[2:])).decode("hex")
        self.datset = str([x[1] for x in main.dataDefault]).replace("['", "").replace("']", "") + '/LLN0$'+ str([x[0] for x in main.dataDefault]).replace("['", "").replace("']", "")
        self.gooseid = main.gooseIDEntry.get()
        self.time1 = int(time.time())
        self.time = (str(hex(self.time1)[2:]) + "00000000").decode("hex")
        self.test = chr(int(main.testEntry.get()))
        self.confrev = chr(int(main.ConfigRevEntry.get()))
        self.ndscom = chr(int(main.ndsComEntry.get()))
        self.numDatSetentries = chr(1)
        self.alldata = 1

        self.length0 = "6c".decode("hex") #Tamanho e tag entre o Reserved 2 e o Goosepdu
        self.length1 = str(hex(len(self.gocbref))[2:]).decode("hex")
        #print self.length1
        self.length2 = "02".decode("hex")
        self.length3 = str(hex(len(self.datset))[2:]).decode("hex")
        self.length4 = ('0' + str(hex(len(self.gooseid))[2:])).decode("hex")
        self.length5 = ('0' + str(hex(len(self.time))[2:])).decode("hex")
        self.length6 = "01".decode("hex")
        self.length7 = "02".decode("hex")
        self.length8 = "01".decode("hex")
        self.length9 = "01".decode("hex")
        self.length10 = "01".decode("hex")
        self.length11 = "01".decode("hex")
        self.length12 = "03".decode("hex")
        self.length13 = "01".decode("hex")

        #self.lengthpdu = str(int(self.length1.encode("hex"),16) + int(self.length2.encode("hex"),16) + int(self.length3.encode("hex"),16) + \
            #int(self.length4.encode("hex"),16)  + int(self.length5.encode("hex"),16)  + int(self.length6.encode("hex"),16)  + \
            #int(self.length7.encode("hex"),16)  + int(self.length8.encode("hex"),16)  + int(self.length9.encode("hex"),16)  + \
            #int(self.length10.encode("hex"),16)  + int(self.length11.encode("hex"),16)  + int(self.length12.encode("hex"),16)  + \
            #int(self.length13.encode("hex"),16)).decode("hex")



        self.goose = GoosePDU(APPID = self.appid, Length = (int(self.length0.encode("hex"),16) + 10), Reserved1 = None, Reserved2 = None)
        self.payload = 'Relay/XCBR1$ST$Loc$stVal'




    def enviaPacote(self, sqNum, stNum):
        time1 = int(time.time())
        time0 = str(int(time.time()*1000000))[8:]
        sqn = "01ee".decode("hex")

        time2 = (str(hex(time1)[2:]) + time0).decode("hex")
        self.pktgoose = self.ethernet/self.prio/self.goose/self.tag0/self.length0/self.tag1/self.length1/self.gocbref\
                        /self.tag2/self.length2/self.timeallow/self.tag3/self.length3/self.datset/self.tag4\
                        /self.length4/self.gooseid/self.tag5/self.length5/time2/self.tag6/self.length6/stNum/\
                        self.tag7/self.length7/sqn/self.tag8/self.length8/self.test/self.tag9/self.length9/\
                        self.confrev/self.tag10/self.length10/self.ndscom/self.tag11/self.length11/self.numDatSetentries/self.tag12/self.length12/self.tag4/self.length13/chr(self.alldata)
        sendp(self.pktgoose, iface = main.ifaceEntry.get())
    def enviaNovoPacote(self, sqNum):
        time1 = int(time.time)
        time0 = str(int(time.time()*1000000))[8:]
        time2 = (str(hex(time1)[2:]) + time0).decode("hex")
        sqn = "01ee".decode("hex")
        self.pktgoose = self.ethernet/self.prio/self.goose/self.tag0/self.length0/self.tag1/self.length1/self.gocbref\
                        /self.tag2/self.length2/self.timeallow/self.tag3/self.length3/self.datset/self.tag4\
                        /self.length4/self.gooseid/self.tag5/self.length5/time2/self.tag6/self.length6/chr(self.stnum + 1)/\
                        self.tag7/self.length7/sqn/self.tag8/self.length8/self.test/self.tag9/self.length9/\
                        self.confrev/self.tag10/self.length10/self.ndscom/self.tag11/self.length11/self.numDatSetentries/self.tag12/self.length12/self.tag4/self.length13/chr(self.alldata + 1)
        sendp(self.pktgoose, iface = main.ifaceEntry.get())


class ChangeEvent(Thread):
    def __init__(self):
      super(ChangeEvent, self).__init__()
      self.change = Thread(target = self.run)
      self.changeSt = False

    def run(self):
        pac = Pacote()
        pac.stnum += 1
        self.changeSt = True

class Enviar(Thread):
    def __init__(self):
        super(Enviar, self).__init__()
        self._stop = Event()
        self.thread = Thread(target=self.run)


    def stop(self):
        self._stop.set()

    def run(self):
        pac = Pacote()
        changeE = ChangeEvent()
        sqNu = 0
        while not self._stop.isSet():
            if(pac.stnumIni == pac.stnum):
                while pac.an < pac.maxtime/pac.q:
                    pac.n = pac.n+1
                    pac.an = int(pac.a1 * (pac.q **(pac.n-1)))
                    print pac.an
                    time.sleep(pac.an/1000)
                    sqNu += 1
                    pac.enviaPacote(sqNum = sqNu, stNum = chr(pac.stnumIni))
                if pac.an >= pac.maxtime/pac.q:
                    pac.an = pac.maxtime
                    print pac.an
                    time.sleep(pac.an/1000)
                    sqNu += 1
                    pac.enviaPacote(sqNum = sqNu, stNum = chr(pac.stnumIni))

            if(pac.stnumIni < pac.stnum):
                print pac.stnumIni
                while pac.an < pac.maxtime/pac.q:
                    pac.n = pac.n+1
                    pac.an = int(pac.a1 * (pac.q **(pac.n-1)))
                    print pac.an
                    time.sleep(pac.an/1000)
                    sqNu += 1
                    pac.enviaPacote(sqNum = sqNu, stNum = chr(pac.stnumIni))
                if pac.an >= pac.maxtime/pac.q:
                    pac.an = pac.maxtime
                    print pac.an
                    time.sleep(pac.an/1000)
                    sqNu += 1
                    pac.enviaPacote(sqNum = sqNu, stNum = chr(pac.stnumIni))
                    pac.n = int(main.sqNumEntry.get())
                    pac.an = int(pac.a1 * (pac.q **(pac.n-1)))
                    print 'comeca a retransmissao...........'
                    print pac.an
                pac.stnumIni += 1
                sqNu = 0
            else:
                if changeE.changeSt == True:
                    time.sleep(pac.maxtime/1000)
                    sqNu += 1
                    pac.enviaNovoPacote(sqNum = sqNu)
                else:
                    time.sleep(pac.maxtime/1000)
                    sqNu += 1
                    pac.enviaPacote(sqNum = sqNu, stNum = chr(pac.stnum))



class Interface:
    def __init__(self,master):
        self.root = root
        self.root.wm_title('Geese')
        self.root.maxsize(width = 600, height=460)
        self.abas = Notebook(master)
        self.frame_aba1 = Frame(self.abas) #Dataset
        self.frame_aba2 = Frame(self.abas) #Packet
        #self.frame_aba3 = Frame(self.abas) #Properties
        self.frame_aba4 = Frame(self.abas) #Send Method

        #self.abas.add(self.frame_aba3, text = 'Properties')
        self.abas.add(self.frame_aba1,text='Dataset')
        self.abas.add(self.frame_aba2,text='Packet')
        self.abas.add(self.frame_aba4, text = 'Send Method')
        self.stepOne = LabelFrame(self.frame_aba2, text=" Information: ")
        self.stepOne.grid(row=0, columnspan=7, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)


        ############################# PROPERTIES ########################################################
        #self.frame3 = LabelFrame(self.frame_aba3, text=" Properties: ")
        #self.frame3.grid(row=0, columnspan=7, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)

        #self.iedName  = Label(self.frame3, text = "IED Name: ")
        #self.iedName.grid(row=0, column=0, padx=5, pady=2, sticky=W)
        #self.iedNameEntry = Entry(self.frame3)
        #self.iedNameEntry.grid(row=1, column=0, columnspan=2, pady=2, sticky= W)

        #self.messageName = Label(self.frame3, text="Message Name: ", )
        #self.messageName.grid(row=2, column=0, sticky='W', padx=2, pady=2)
        #self.messageEntry = Entry(self.frame3, width = 40)
        #self.messageEntry.grid(row=3, column=0, columnspan=7, sticky="W", pady=2, padx =2)

        #self.description = Label(self.frame3, text="Description: ")
        #self.description.grid(row=4, column=0, sticky='W', padx=2, pady=2)
        #self.descripEntry = Text(self.frame3, height = 3, width = 40)
        #self.descripEntry.grid(row=5, column=0, columnspan=7, sticky="WE", pady=2)

        #self.fecha = Button(self.frame_aba3, text = 'Exit', width = 5, command= fechar)
        #self.fecha.grid(row = 8, column = 10, padx = 5, sticky = 'NESW')
        ################################################################################################
        ##############################################################################################

        ########################GOOSE PDU INFO#####################################################

        self.frame2 = LabelFrame(self.frame_aba2, text=" GoosePDU Info: ")
        self.frame2.grid(row=0, columnspan=7, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)

        self.gooseID = Label(self.frame2, text="GooseID: ")
        self.gooseID.grid(row=1, column=0, sticky='W', padx=2, pady=2)
        self.gooseIDEntry = Entry(self.frame2)
        self.gooseIDEntry.grid(row=2, column=0,  sticky=W, pady=2)

        self.ConfigRev = Label(self.frame2, text="Configuration Revision: ")
        self.ConfigRev.grid(row=3, column=0, sticky='W', padx=2, pady=2)
        self.ConfDefault = StringVar(root)
        self.ConfDefault.set('1')
        self.ConfigRevEntry = Entry(self.frame2, textvariable=self.ConfDefault)
        self.ConfigRevEntry.grid(row=4, column=0, sticky="W", pady=2)


        self.AppID = Label(self.frame2, text="APP ID: ")
        self.AppID.grid(row=5, column=0, sticky='W', padx=2, pady=2)
        self.AppIDEntry = Entry(self.frame2)
        self.AppIDEntry.grid(row=6, column=0, columnspan=2, sticky='W', padx=2, pady=2)

        self.VLANID = Label(self.frame2, text="VLAN ID: ")
        self.VLANID.grid(row=7, column=0, sticky='W', padx=2, pady=2)
        self.VLANIDEntry = Entry(self.frame2)
        self.VLANIDEntry.grid(row=8, column=0, columnspan=2, sticky='W', padx=2, pady=2)

        self.VlanPriority = Label(self.frame2,text="VLAN PRIORITY: ")
        self.VlanPriority.grid(row=9, column=1, sticky='W', padx=2, pady=2)
        self.variable = IntVar(self.frame2)
        self.variable.set("4")
        self.getFldChk = OptionMenu(self.frame2, self.variable,'', '0', '1', '2', '3', '4','5','6','7')
        self.getFldChk.grid(row=10, column=1, sticky='W', padx=2, pady=2)

        self.MACaddress = Label(self.frame2, text="MAC Multicast Address: ")
        self.MACaddress.grid(row=1, column = 9, sticky = 'W')
        self.MACdefault = StringVar(root)
        self.MACdefault.set('01:0C:CD:01:00:00')
        self.MACaddressEntry = Entry(self.frame2,  textvariable= self.MACdefault )
        self.MACaddressEntry.grid(row=2, column=9,sticky='W', padx=2, pady=2)

        self.MACSource = Label(self.frame2, text="MAC Address Source: ")
        self.MACSource.grid(row= 3, column = 9, sticky = 'W')
        self.MACSourceEntry = Entry(self.frame2)
        self.MACSourceEntry.grid(row=4, column=9, sticky='W', padx=2, pady=2)

        self.test = Label(self.frame2, text="Test: ")
        self.test.grid(row=5, column=9,sticky='W', padx=5, pady=5)
        self.testEntry = Entry(self.frame2, width = 10)
        self.testEntry.grid(row=6, column=9, sticky='W', padx=2, pady=2)

        self.ndsCom = Label(self.frame2, text="NdsCom: ")
        self.ndsCom.grid(row=7, column=9, sticky='W', padx=2, pady=2)
        self.ndscomDefault = IntVar(self.frame2)
        self.ndscomDefault.set(0)
        self.ndsComEntry = Entry(self.frame2, width = 10, textvariable= self.ndscomDefault)

        self.ndsComEntry.grid(row=8, column=9, sticky='W', padx=2, pady=2)


        ########################################## SEND METHOD ###############################
        #########################################################################################################
        self.frame4 = LabelFrame(self.frame_aba4, text="Send Method: ")
        self.frame4.grid(row=0, columnspan=7, sticky='W', padx=5, pady=5, ipadx=5, ipady=5)

        self.select = Label(self.frame4,text="Select: ")
        self.select.grid(row=1, column=1, sticky='W', padx=2, pady=2)
        self.variable1 = StringVar(self.frame4)
        self.variable1.set('PG')
        self.selectopt = OptionMenu(self.frame4, self.variable1, 'PG')
        self.selectopt.grid(row=2, column=1, sticky='W', padx=2, pady=2)

        self.iface = Label(self.frame4, text = "Interface: ")
        self.iface.grid(row = 1, column = 3, sticky = 'W', padx = 2, pady = 2)
        self.ifaceEntry = Entry(self.frame4, width = 10)
        self.ifaceEntry.grid(row = 2, column = 3, sticky = 'W', padx = 2, pady = 2)

        #self.variable2 = StringVar(self.frame4)
        #self.variable2.set('eth0')
        #self.selectopt1 = OptionMenu(self.frame4, self.variable2, '', 'eth0', 'wlan0', 'eth1', 'lo')
        #self.selectopt1.grid(row=2, column=3, sticky='W', padx=2, pady=2)


        self.razao = Label(self.frame4, text = "Ratio: ")
        self.razao.grid(row = 1, column = 2, sticky = 'W', padx = 2, pady = 2)
        self.razaovar = IntVar()
        self.razaoEntry = Entry(self.frame4, width = 10)
        self.razaoEntry.grid(row = 2, column = 2, sticky = 'W', padx = 2, pady = 2)


        self.minTime = Label(self.frame4, text="Min.Time(ms)")
        self.minTime.grid(row=3,column=1, sticky='W', padx=2, pady=2)
        self.minTimeEntry = Entry(self.frame4)
        self.minTimeVar = IntVar()
        self.minTimeEntry.grid(row=4, column=1, sticky='W', pady=2)
        self.minTimeEntry.insert(0, '1')

        self.maxTime = Label(self.frame4, text="Max.Time(ms)")
        self.maxTime.grid(row=3, column=2, padx=10, pady=2, sticky = W)
        self.maxTimeDefault = IntVar()
        self.maxTimeDefault.set(1000)
        self.maxTimeEntry = Entry(self.frame4, textvariable = self.maxTimeDefault)
        self.maxTimeEntry.grid(row=4, column=2, pady=2, padx = 10, sticky = 'W')




        self.timeAllow = Label(self.frame4, text="Time Allowed to Live: ")
        self.timeAllow.grid(row=5, column = 1, sticky = 'W')
        self.timeAllowDefault = IntVar()
        self.timeAllowDefault.set(self.maxTimeDefault.get() * 2)
        self.timeAllowEntry = Entry(self.frame4, width = 10, textvariable = self.timeAllowDefault)
        self.timeAllowEntry.grid(row=6, column=1, columnspan=2, sticky='W', padx=5, pady=5)

        self.stNum =  Label(self.frame4, text="stNum: ")
        self.stNum.grid(row=7, column=1, columnspan=2, sticky='W', padx=5, pady=5)
        self.stNumEntry = Entry(self.frame4, width = 10)
        self.stNumEntry.grid(row=8, column=1, columnspan=2, sticky='W', padx=5, pady=5)


        self.sqNum = Label(self.frame4, text="sqNum: ")
        self.sqNum.grid(row=7, column=2,  sticky='W', padx=5, pady=5)
        self.sqNumvar = IntVar()
        self.sqNumvar.set(0)
        self.sqNumEntry = Entry(self.frame4, width = 10, state = DISABLED, textvariable = self.sqNumvar)
        self.sqNumEntry.grid(row=8, column=2, columnspan=2, sticky='W', padx=5, pady=5)

        self.abas.grid(row = 0, column = 0)


        ########################## DATASET ###################################################
        f = Frame(self.frame_aba1)
        f.grid(row = 2, column = 0 , sticky = 'W', padx = 2, pady =2 )
        self.dataCols = ('Name', ' Phisical Device', 'Description', 'Reference')
        self.tree = Treeview(f, columns=self.dataCols,show = 'headings')
        for c in self.dataCols:
            self.tree.heading(c, text=c.title())
            self.tree.column(c, width= 100)
        self.tree.grid(row=2, column=0, sticky='W', padx=2, pady=2)
        self.n = Newdataset

        self.data1 = [

            ("", "")


                      ]

        self.dataDefault = [("DSet13", "SEL_451_1CFG", "Dataset Padrao", "")]

        for self.item in self.dataDefault:
            self.tree.insert('', 'end', values=self.item)


        n = Newdataset()
        self.delete = Button(self.frame_aba1, text = 'Delete', width = 5, command = n.delButton)
        self.delete.grid(row = 10, column = 0, padx = 5, sticky = 'W')

        self.edit = Button(self.frame_aba1, text = 'Edit', width = 5, command = n.editButton)
        self.edit.grid(row = 10, column = 1, padx = 5, sticky = 'SW')

        self.new = Button(self.frame_aba1, text = 'New DataSet', width = 10, command = n.addNewindow)
        self.new.grid(row = 10, column = 2, padx = 5, sticky = 'W')




class Newdataset:

    def addNewindow(self):

            self.window = Toplevel()

            self.Name  = Label(self.window, text = "Name: ")
            self.Name.grid(row=1, column=0, padx=5, pady=2, sticky=W)
            self.Namevar = StringVar()
            self.Namevar.set("DSet13")
            self.NameEntry = Entry(self.window, textvariable = self.Namevar)
            self.NameEntry.grid(row=2, column=0, columnspan=2, pady=2, sticky= W)

            self.pDevice = Label(self.window, text = 'Phisical Device:')
            self.pDevice.grid(row=1, column= 2, padx = 5, pady =2, sticky = N)
            self.pDeviceVar = StringVar(self.window)
            self.pDeviceVar.set("SEL_451CFG")
            self.pDeviceMenu = OptionMenu(self.window, self.pDeviceVar, '', 'SEL_451CFG')
            self.pDeviceMenu.grid(row=2, column=2, columnspan=2, padx = 10, pady=2, sticky= E)

            self.ldevice = Label(self.window, text = 'Logical Device')
            self.ldevice.grid(row = 3, column = 0, padx = 3, pady = 3, sticky =W)
            self.ldevVariable = StringVar(self.window)
            self.ldevVariable.set("CSWI")
            self.ldeviceMenu = OptionMenu(self.window, self.ldevVariable, '', 'CSWI', 'RBRF', 'PSCH')
            self.ldeviceMenu.grid(row=4, column=0, sticky='W', padx=2, pady=2)

            self.prefix = Label(self.window, text = 'Prefix')
            self.prefix.grid(row = 3, column = 1, padx = 3, pady = 3, sticky =W)
            self.prefixvar = StringVar(self.window)
            self.prefixvar.set("BKR1")
            self.prefixMenu = OptionMenu(self.window,self.prefixvar, '', 'BKR1','BFR1','DCUB')
            self.prefixMenu.grid(row = 4, column = 1, padx = 3, pady = 3, sticky = W)

            self.lnode = Label(self.window, text = 'Logical Node')
            self.lnode.grid(row = 3, column = 2, padx = 3, pady = 3, sticky =W)
            self.lnodevar = StringVar()
            self.lnodevar.set("RBRF")
            self.lnodeMenu = OptionMenu(self.window, self.lnodevar, '', 'CSWI', 'RBRF', 'PSCH')
            self.lnodeMenu.grid(row = 4, column = 2, padx = 3, pady = 3, sticky = W)

            self.sufix = Label(self.window, text = 'Sufix')
            self.sufix.grid(row = 3, column = 3, padx = 3, pady = 3, sticky =W)
            self.sufixvar = StringVar()
            self.sufixvar.set("1")
            self.sufixMenu = OptionMenu(self.window, self.sufixvar, '', '1', '3')
            self.sufixMenu.grid(row = 4, column = 3, padx = 3, pady = 3, sticky = W)

            self.dtObj = Label(self.window, text = 'Data Object')
            self.dtObj.grid(row = 3, column = 4, padx = 3, pady = 3, sticky =W)
            self.dtObjvar = StringVar()
            self.dtObjvar.set("Pos.Oper")
            self.dtObjMenu = OptionMenu(self.window, self.dtObjvar, '', 'Pos.Oper', 'OpIn', 'ProRx', 'ProTx')
            self.dtObjMenu.grid(row = 4, column = 4, padx = 3, pady = 3, sticky = W)


            self.dtAtribbute = Label(self.window, text = 'Attribute')
            self.dtAtribbute.grid(row = 3, column = 5, padx = 3, pady = 3, sticky =E+W)
            self.dtAtribbutevar = StringVar()
            self.dtAtribbutevar.set("ctlVal")
            self.dtAtribbuteMenu = OptionMenu(self.window, self.dtAtribbutevar, '', 'ctlVal', 'general', 'stVal')
            self.dtAtribbuteMenu.grid(row = 4, column = 5, padx = 3, pady = 3, sticky = E+W)

            self.description = Label(self.window, text = 'Description: ')
            self.description.grid(row = 5, column = 0, padx = 3, pady = 5, sticky = W)
            self.descriptionvar = StringVar()
            self.descriptionEntry = Text(self.window, height = 3, width = 40)
            self.descriptionEntry.grid(row= 6, column=0, columnspan=500, sticky= W, pady=2)

            self.add = Button(self.window, text = 'Add', width = 5, command = lambda: self.addButton(self.NameEntry,self.descriptionEntry))
            self.add.grid(row = 7, column = 5, padx = 5, sticky = 'NESW')


    def addButton(self,NameEntry, descriptionEntry ):

      self.name1 = NameEntry.get()
      self.pdev1 = self.pDeviceVar.get()
      self.wholedata = self.ldevVariable.get() + '.' + self.prefixvar.get() + '.' + self.lnodevar.get() + '.' + self.sufixvar.get() + '.' + self.dtObjvar.get() + '.' + self.dtAtribbutevar.get()
      self.descript = descriptionEntry.get(1.0, END)
      main.data1 = [(self.name1, self.pdev1, self.descript, self.wholedata)]

      for self.item in main.data1:
        main.tree.insert('', 'end', values=self.item)

      self.window.destroy()

    def delButton(self):
        self.selected_item = main.tree.selection()[0] ## get selected item
        main.tree.delete(self.selected_item)



    def editButton(self):
        self.selected_item2 = main.tree.selection()[0]
        self.addNewindow()
        main.tree.delete(self.selected_item2)



def fechar():
        root.destroy()

if __name__ == "__main__":

    root = Tk()
    main = Interface(root)
    changeE =  ChangeEvent()
    envia = Enviar()

    def startCallBack():
        if main.razaoEntry.get() == '':
            print "Campo Vazio!"
        else:
            envia.start()



    start_button = Button(main.frame4, text="Send", command = startCallBack)
    start_button.grid(row = 70, column = 3, padx = 5, sticky = 'NESW')



    def stopCallBack():
        envia.stop()

    def startChange():
        changeE.start()




    stop_button = Button(main.frame4, text = "Stop", command = stopCallBack)
    stop_button.grid(row = 70, column = 2, padx = 5, sticky = 'NESW')

    changeEventButton = Button(main.frame4, text = "Change Event", command = startChange)
    changeEventButton.grid(row = 70, column = 1, padx = 5, sticky = 'NESW')

    class GoosePDU(Packet):
        name = "Goose"
        fields_desc=[ShortField("APPID", 0),
                    ShortField("Length", 0),
                    ShortField("Reserved1", 0),
                    ShortField("Reserved2", 0),
                    ]






    #prio = Dot1Q(prio=6,id=0,vlan=0)
    #prio.fields_desc[3]=XShortEnumField("type",0x88b8,ETHER_TYPES)


    payload='Relay1/XCBR1$ST$Loc$stVal'

#Definindo origem e destino
##ethernet = Ether(dst=sys.argv[1],src=sys.argv[2])

root.mainloop()

