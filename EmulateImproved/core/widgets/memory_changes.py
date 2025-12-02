import binaryninja
from binaryninja import BinaryView
from binaryninjaui import (
	SidebarWidget,
	SidebarWidgetType,
	Sidebar,
	ViewFrame,
	UIContextNotification,
	UIContext,
	ViewLocation,
	View,
)
from binaryninjaui import getMonospaceFont

from PySide6.QtCore import Qt, QRectF, QSize
from PySide6.QtGui import QImage, QStandardItemModel, QStandardItem
from PySide6.QtWidgets import (
	QVBoxLayout,
	QListView,
	QTreeView,
	QWidget,
	QCheckBox,
	QHBoxLayout,
	QHeaderView,
)

from threading import Thread
import os


class ChangedMemorySidebar(SidebarWidget, UIContextNotification):
	def __init__(self, title: str, frame: ViewFrame, bv: BinaryView):
		SidebarWidget.__init__(self, title)

		self.frame = frame
		self.bv = bv

		self.model = QStandardItemModel(self)
		self.list = QListView(self)
		self.list.setModel(self.model)

		self.model = QStandardItemModel(0, 4)  # 0 rows, 2 columns
		self.model.setHorizontalHeaderLabels(
			["Address", "Length", "Original bytes", "Patched bytes"]
		)
		self.add_item("0x10000", "12", "a" * 12, "b" * 12)
		self.add_item("0x20000", "16", "c" * 16, "d" * 16)
		self.add_item("0x30000", "1", "e", "f")

		self.model.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

		self.layout = QVBoxLayout()
		self.layout.setContentsMargins(0, 0, 0, 0)
		self.layout.addWidget(self.list)

	def add_item(self, addr, size, orig, patched):
		row_count = self.model.rowCount()
		self.model.insertRow(row_count)
		self.model.setItem(row_count, 0, QStandardItem(addr))
		self.model.setItem(row_count, 1, QStandardItem(size))
		self.model.setItem(row_count, 2, QStandardItem(orig))
		self.model.setItem(row_count, 3, QStandardItem(patched))

	def __del__(self):
		UIContext.unregisterNotification(self)


class ChangedMemorySidebarType(SidebarWidgetType):
	def __init__(self):
		# Sidebar icons are 28x28 points. Should be at least 56x56 pixels for
		# HiDPI display compatibility. They will be automatically made theme
		# aware, so you need only provide a grayscale image, where white is
		# the color of the shape.

		icon = QImage(
			os.path.join(os.path.dirname(__file__), "icons", "memory_diff_widget_logo.png")
		)
		SidebarWidgetType.__init__(self, icon, "[EmulateImproved] Changed Memory")

	def createWidget(self, frame: ViewFrame, data: BinaryView):
		return ChangedMemorySidebar("[EmulateImproved] Changed Memory", frame, data)


# Deferred registration to see if a first-party plugin with this name
# supersedes us
def register():
	if not Sidebar.isTypeRegistered("[EmulateImproved] Changed Memory"):
		Sidebar.addSidebarWidgetType(ChangedMemorySidebarType())


# Gross hack to wait for the main thread to start
Thread(target=lambda: binaryninja.execute_on_main_thread(register)).start()
