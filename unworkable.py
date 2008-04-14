# Copyright (c) 2008 Harry Tormey <slander@unworkable.org>
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

#------------------------------------------------------------------------
# Demo allows you to add torrents to a custom wxpython grid. For every 
# torrent selected a listener thread and a simulator thread are initialized
# and grid is updated. The simulator threads (class torrent) are for debug/testing
# purposes only, they simulate the messages that would be sent by an instance of 
# unworkable to the gui. Included with this file is code to run an instance of unworkable.exe
# as a seperate thread. This is currently disabled.
#------------------------------------------------------------------------
#	April 13
#	+unworkable.exe to listener communication inconsistant and barely usable.
#	March 31 TODO (ordered by priority):
#	+Delete torrent button:
#		*Add a check box to grid.
#		*clicking delete, removes all running torrents from grid
#		*Need a way to terminate instances of unworkable, stop listener threads
#	+Log
#		*Debug information (what function called when, exceptions, etc) to logfile
#	+Status bar
#		*figure out how to draw and update coloured rectangles in grid
#	+Unit tests
#		*Read up on writing Unit tests for gui/network apps.
#		*integrate emulator.py into unworkable.pyu code
#
#
import  wx.grid as  gridlib
import  wx
import  wx.lib.newevent
import  os
import subprocess
import  getopt
import  socket
import  thread
import  threading
import  Queue
import  time
import  random

#---------------------------------------------------------------------------
# This is how you pre-establish a file filter so that the dialog
# only shows the extension(s) you want it to.
wildcard = "Torrent files (*.torrent)|*.torrent|"    \
           "All files (*.*)|*.*"
#---------------------------------------------------------------------------
# Same as above but just show exe's (windows, fix this for linux/osx)
exeWildcard = "exe files (*.exe)|*.exe|"    \
           "All files (*.*)|*.*"
#----------------------------------------------------------------------

# This creates a new Event class and a EVT binder function
# Usage: An unworkable listener thread sends out an EVT_UPDATE_GRID
# message every time new information is received from the unworkable
# client processing a given torrent.

(UpdateGridEvent, EVT_UPDATE_GRID) = wx.lib.newevent.NewEvent()

#This emulates an instance of unworkable, it waits for connections on a given port
class torrent(threading.Thread):
	'''Send message to conn.py simulating unworkable'''
	def __init__(self, host, port):
		self.host = host
		self.port = port
		self.num_peers = 0
		self.num_pieces = 0
		self.torrent_size = 0
		self.torrent_bytes = 0
		self.pieces = []
		self.peers = []
		self.bytes = 0
		self._done = False
		self.quit = False
		self._f = None
		self.counter = 0
		self.running = False
		#setup socket to listen for tcp/ip on host/port
		self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._socket.bind((host, port))
		self._socket.listen(5)
		self.keepGoing = False
		threading.Thread.__init__(self)
	def Start(self):
		self.keepGoing = self.running = True
		thread.start_new_thread(self.run, ())
	def IsRunning(self):
		return self.running
	def Stop(self):
		#self._f.close()
		self._done = True
		self._socket.close()
		self.keepGoing = False
		self.quit = True
	def run(self):
		try:
				# program will wait for connections
				# to terminate, hit ctrl c/ctrl break
				print "waiting for conntections \n"
				newSocket, address = self._socket.accept( )
				print "Connected from", address
				self._f = newSocket.makefile()
				numbytes = 0
				while self.keepGoing:
				#while numbytes < 100:

					message = 'num_peers:%d\r\nnum_pieces:%d\r\ntorrent_size:%d\ntorrent_bytes:%d\r\n' % (10,0,2,numbytes)
					self._f.write(message)
					self._f.flush()
					print message
					time.sleep(1)
					numbytes += 1
				self._f.close()
				self._socket.close()
				self.running = False
		except socket.error, e:
			print e
			#print and ignore all socket errors
			pass
		except  KeyboardInterrupt, e:
			#print and stop on keyboard interrupt
			print e
			self.stop()

#This creates an instance of unworkable.exe
class unworkable():
	''''Run an instance of unworkable.exe as a sepetate thread'''
	def __init__(self, host, port, torrent, path, log, handler=None): 
		#Adress of host (currently not used)
		self.host = host
		#Tell unworkable.exe to speak to unworkablelistener class on this port
		self.port = port
		#Name of the torrent we are downloading 
		self.torrent = torrent
		#Path to unworkable.exe
		self.path = path
		#Trace file where log output from unworkable.exe gets dumped.
		self.log = log
		#Variable which will eventually be used to kill the subprocess (currently not used)
		self.keepGoing = False
		#subprocess
		self.process = None
		#Set up function to be run in background thread
		self.t = threading.Thread(target=self.Run)
		#This setting might not do anything
		self.t.setDaemon(True)
		#The actual command that gets executed
		self.cmd = ('%s -t %s -g %i %s' % (self.path, self.log, self.port, self.torrent))
	def Stop(self):
		#Change this to kill a process.
		self.keepGoing = False
	def Start(self):
		#start the thread
		self.keepGoing = True
		self.t.start()
	def Run(self):
		self.process = subprocess.Popen(self.cmd)

#----------------------------------------------------------------------
# UnworkableListener listens for information from instances of unworkable.exe
# and passes output back to mainwindow.
#----------------------------------------------------------------------

class UnworkableListener:
	def __init__(self, win, barNum, val, host, port):
		self.win = win
		self.barNum = barNum
		self.val = val
		self.host = host
		self.port = port
		self.num_peers = 0
		self.num_pieces = 0
		self.torrent_size = 0
		self.torrent_bytes = 0
		self.pieces = []
		self.peers = []
		self.bytes = 0
		self._socket = None
		self._f = None
		self.keepGoing = False
		self.running = False
	def Start(self):
		print "listener started \n"
		self.keepGoing = self.running = True
		thread.start_new_thread(self.Run, ())

	def Stop(self):
		self.keepGoing = False
		#self._f.close()

	def IsRunning(self):
		return self.running
	def Run(self):
		try:
			self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			self._socket.connect_ex((self.host, self.port))
			self._f = self._socket.makefile()
		except socket.error, e:
			#ignore all socket errors
			pass
		try:
			#keep polling for information from uworkable.exe
			while self.keepGoing:
				print "listener still looping \n"
				for l in self._f:
					try:
						d = l.strip().split(':', 1)
					except:
						# ignore malformed line
						continue
					if d[0] == 'num_peers':
						if not isinstance(d[1], int):
							continue
						self.num_peers = int(d[1])
					elif d[0] == 'num_pieces':
						self.num_pieces = int(d[1])
					elif d[0] == 'torrent_size':
						self.torrent_size = int(d[1])
					elif d[0] == 'torrent_bytes':
						self.torrent_bytes = int(d[1])
					elif d[0] == 'pieces':
						try:
							new_pieces = d[1].split(',')
							new_pieces.sort()
							self.pieces = new_pieces
						except:
							# no pieces yet
							continue
					elif d[0] == 'bytes':
						self.bytes = int(d[1])
					elif d[0] == 'peers':
						try:
							new_peers = d[1].split(',')
							new_peers.sort()
							self.peers = new_peers
						except:
							# no peers yet
							continue
					else:
						print "unkown message: %s" %(l)
					#Create an update grid event with all messages received from unworkable.exe
					evt = UpdateGridEvent(self.barNum) 
							#self.num_peers)
							#self.num_pieces, 
							#self.torrent_size,
							#self.torrent_bytes)
							#self.pieces,
							#self.bytes,
							#self.peers)
					#post event for mainwindow to process
					wx.PostEvent(self.win, evt)
					
		except socket.error, e:
			#ignore all socket errors sleep for 5 seconds and run again
			time.sleep(1)
			self.run()
		self.running = False

#----------------------------------------------------------------------
# This is where all the information from unworkablelistener threads gets 
# stored/updated.
#----------------------------------------------------------------------
class CustomDataTable(gridlib.PyGridTableBase):
	def __init__(self):
		gridlib.PyGridTableBase.__init__(self)
		self.numCols = 13
		self.colLabels = ['#', 'Name', 'Size', 'Done', 'Seeds',
				'Peers', 'Down Speed', 'Up Speed', 'ETA', 'Uploaded', 'Ratio','Port', 'Avail']
		self.dataTypes = [gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_STRING,
					gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_NUMBER ,
					gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_FLOAT,
					gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_NUMBER,
					gridlib.GRID_VALUE_NUMBER]
		#Blank entry
		self.data = []
		for i in range(1,2):
			self.data.append([0, "", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])

	def GetNumberRows(self):
		return len(self.data) + 1

	def GetNumberCols(self):
		return len(self.data[0])

	def IsEmptyCell(self, row, col):
		try:
			return not self.data[row][col]
		except IndexError:
		    return True

	#Get value from row/col
	def GetValue(self, row, col):
		try:
			return self.data[row][col]
		except IndexError:
			return ''
	#Update row from passed entry
	def UpdateEntry(self, row, entry):
		#for col in range(1, self.numCols):
		col = 0
		for value in entry:
				self.SetValue(row, col, value)
				col = col + 1
		#self.GetView().ProcessTableMessage(msg)
		#self.ForceRefresh()


	#Add another entry to the grid.
	def appendEntry(self, entry):
		self.data.append(entry)
		msg = gridlib.GridTableMessage(self,            # The table
		       gridlib.GRIDTABLE_NOTIFY_ROWS_APPENDED, # what we did to it
		       1                                       # how many
		       )
		self.GetView().ProcessTableMessage(msg)

	def SetValue(self, row, col, value):
		try:
			self.data[row][col] = value
		except IndexError, e:
			print e
			
	def GetColLabelValue(self, col):
		return self.colLabels[col]

	def GetTypeName(self, row, col):
		return self.dataTypes[col]

	def CanGetValueAs(self, row, col, typeName):
		colType = self.dataTypes[col].split(':')[0]
		if typeName == colType:
			return True
		else:
			return False

	def CanSetValueAs(self, row, col, typeName):
		return self.CanGetValueAs(row, col, typeName)

#---------------------------------------------------------------------------
# This handles how custom data table is displayed/controlled in the frame
# used by main window.
#---------------------------------------------------------------------------
class CustTableGrid(gridlib.Grid):
	def __init__(self, parent):
		gridlib.Grid.__init__(self, parent, -1)
		table = CustomDataTable()
		self.table = table
		self.SetTable(table, True)
		self.SetRowLabelSize(0)
		self.SetMargins(0,0)
		self.AutoSizeColumns(False) # Maybe set this to true
		gridlib.EVT_GRID_CELL_LEFT_DCLICK(self, self.OnLeftDClick)
	def OnLeftDClick(self, evt):
		if self.CanEnableCellControl():
			self.EnableCellEditControl()
	def appendEntry(self):
		self.table.appendEntry()

#Main window/frame
class mainwindow(wx.Frame):
	def __init__(self, parent):
		#Path to unworkable.exe
		self.unworkable = './unworkable.exe'
		#currently just holds option to specify port for unworkable
		self.unworkableOptionPort = '-g'
		#Set the inital value of process to none
		self.process = None
		#Counts the number of listener threads running. Displayed under # in gui
		self.NumThreads = 0
		#map a port to each listener thread. Displayed under port in gui
		self.ThreadPort = 5000
		#Initialize the frame
		wx.Frame.__init__(self, parent, -1, "unworkable", size=(590,490))
		#setup the panel where all widgets will live
		self.p = wx.Panel(self, -1, style=0)
		#create instance of custom grid
		grid = CustTableGrid(self.p)
		self.grid = grid
		#Number of rows, cols in customdatatable
		self.numRow  = self.grid.table.GetNumberRows()
		self.numCols = 13
		#A simple sizer to control the layout of the widgets
		#Within the frame
		self.bs = wx.BoxSizer(wx.VERTICAL)
		self.bs.Add(grid, 1, wx.GROW|wx.ALL, 5)
		#Add Delete, path and open buttons + bind them to functions 
		#+ add them to the sizer bs.
		self.createButtons(self.p)
		self.p.SetSizer(self.bs)
		#This event checks for a update event posted by a thread
		self.Bind(EVT_UPDATE_GRID, self.OnUpdate)
		#This event checks for a close screen event, 
		#i.e to kill all  active threads
		self.Bind(wx.EVT_CLOSE, self.OnCloseWindow)
		#Set up a list of unworkable torrent listener/unworkable.exe threads
		self.threads = []
		#Setup unworkable.exe thread to feed data to listener with host,port,torrent,path, log handler (default=None)
		#self.threads.append(unworkable("localhost", self.ThreadPort, "fiore_thesis_final.pdf.torrent", self.unworkable, "5000.log"))
		#Setup listener
		#self.threads.append(UnworkableListener(self, self.NumThreads, self.NumThreads, "localhost", self.ThreadPort))

		#Example of how to append data to grid
		#entry = [self.NumThreads, 'Testtorrent', "critical", 0, 'all', 0, 0, 0, self.ThreadPort, 0.0]
		#self.grid.table.SetValue(self.NumThreads, 0, self.NumThreads)
		#self.grid.table.SetValue( self.NumThreads, 1, "testtorrent")
		#self.grid.table.SetValue( self.NumThreads, 11, self.ThreadPort)
		#self.Refresh(False)

		#self.grid.table.appendEntry(entry)
		#self.NumThreads += 1
		#self.ThreadPort += 1
		#start all threads
		#for t in self.threads:
		#	t.Start()

	#Add all buttons to GUI
	def buttonData(self):
		return (("Delete", self.DelButton),
			("Path", self.PathButton),
			("Open", self.OpenButton))

	#Iterate through the entries returned by buttonData and populate the
	#screen
	def createButtons(self, panel):
		for eachLabel, eachHandler in self.buttonData():
			button = wx.Button(self.p, -1, eachLabel)
			button.SetDefault()
			self.Bind(wx.EVT_BUTTON, eachHandler, button)
			self.bs.Add(button)

#----End of process stuff
	#def buttonData(self):
	#	return
	def AddButton(self, evt):
		print "ADD button selected"
		self.grid.table.TestUpdateGrid()
	def DelButton(self, evt):
		print "Delete button selected"
	def OnButtonFocus(self, evt):
		print "button focus"
	#When update message received post value and refresh the screen
	def OnUpdate(self, evt):
		#self.grid.table.SetValue(evt.barNum, 2, evt.torrent_size)
		#formula for how much is done
		#percent = ((float)*good_pieces / num_pieces) * 100;
		self.grid.table.SetValue(evt.barNum, 3, evt.num_pieces)
		print "Bar number"
		print evt.barNum
		print evt.num_pieces
		self.grid.table.SetValue(evt.barNum, 5, evt.num_peers)
		print evt.num_peers
		self.grid.table.SetValue(evt.barNum, 6, evt.torrent_bytes)
		print evt.torrent_bytes
		#Tell the gui to refresh screen
		self.Refresh(False)
#	1)Open torrent button:
#		*Button should produce a dialog to select a torrent. 
#		*Upon Selection torrent name should be added to dialog,
#		*a new instance of unworkable listener should be created
#		*a new instance of unworkable should be run with an incremented port number
	def OpenButton(self, evt):
		dlg = wx.FileDialog(
		self, message="Choose a file",
		defaultDir=os.getcwd(),
		defaultFile="",
		wildcard=wildcard,
		style=wx.OPEN | wx.MULTIPLE | wx.CHANGE_DIR
		)
		if dlg.ShowModal() == wx.ID_OK:
			# This returns a Python list of files that were selected.
			paths = dlg.GetPaths() # Be carefull of GetPath, this just gets path to one file
			
			for path in paths:
				#Start listening on barnum?
				#Split the path into filename, directories
				folders, fileName = os.path.split(path)
				#Split the file extension from the filename
				(fileBaseName, fileExtension)=os.path.splitext(fileName)
				#Make sure that each entry in the custom table, corresponds with a thread
				entryNumber = len(self.threads)
				entry = [self.NumThreads, fileBaseName, 0, 0, 0, 0, 0, 0, 0, 0, 0, self.ThreadPort, 0.0]
				#Setup unworkable.exe thread to feed data to listener with host,port,torrent,path, 
				#log handler (default=None)
				unworkableBinary = unworkable("localhost", self.ThreadPort, fileName, 
				self.unworkable, "5000.log")
				#Setup listener
				listener = UnworkableListener(self, self.NumThreads, self.NumThreads, "localhost", 
				self.ThreadPort)
				if(entryNumber < self.numRow):
					print entryNumber
					#Update entry corresponding to new thread added
					self.grid.table.UpdateEntry(entryNumber, entry)
					#place holder till I get the threads consolidated
					self.threads.append([entryNumber, unworkableBinary, listener])
					#Tell the gui to refresh screen
					self.Refresh(False)
				else:
					self.grid.table.appendEntry(entry)
					self.threads.append([entryNumber, unworkableBinary, listener])
					#unworkable.Start()
					#listener.Start()
				listener.Start()
				unworkableBinary.Start()
				#Start torrent simulator
				#self.threads.append(torrent("localhost", self.ThreadPort))
				#self.threads[(len(self.threads) -1)].Start()
				#Start unworkablelistener thread
				#self.threads.append(UnworkableListener(self, self.NumThreads, self.NumThreads, "localhost", self.ThreadPort))
				#self.threads[(len(self.threads) -1)].Start()
				#Increment counters
				#self.NumThreads += 1
				self.ThreadPort += 1
		dlg.Destroy()
	def PathButton(self, evt):
		dlg = wx.FileDialog(
		self, message="Set unworkable path",
		defaultDir=os.getcwd(),
		defaultFile="",
		wildcard=exeWildcard,
		style=wx.OPEN | wx.MULTIPLE | wx.CHANGE_DIR
		)
		if dlg.ShowModal() == wx.ID_OK:
			# This returns the path (just one) of the .exe selected.
			self.unworkable = dlg.GetPath() # Be carefull of GetPath, this just gets path to one file
			
		dlg.Destroy()
	def OnCloseWindow(self, evt):
		#Display a busy message dialog while all threads are being killed off
		busy = wx.BusyInfo("One moment please, waiting for threads to die...")
		wx.Yield()
		#stop all active threads
		for t in self.threads:
			t.Stop()
		# keep looping till all threads stop running
		running = 1
		while running:
			running = 0
			for t in self.threads:
				running = running + t.IsRunning()
			time.sleep(0.1)
		#destroy window
		self.Destroy()

#---------------------------------------------------------------------------
if __name__ == '__main__':
	import sys
	app = wx.PySimpleApp()
	frame = mainwindow(None)
	frame.Show(True)
	app.MainLoop()
