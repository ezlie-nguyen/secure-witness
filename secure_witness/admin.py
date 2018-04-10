from django.contrib import admin
from models import *

class FileAdmin(admin.ModelAdmin):
	readonly_fields = ('date_modified', 'date_created',)
	fieldsets = [
		(None, {'fields': ['author', 'bulletin', 'name']}),
		('Date information', {'fields': ['date_created', 'date_modified']}),
	]
	list_display = ('name', 'author', 'bulletin', 'date_created', 'date_modified')

class FileInline(admin.TabularInline):
	model = File
	extra = 0

class BulletinAdmin(admin.ModelAdmin):
	readonly_fields = ('date_modified', 'date_created',)
	fieldsets = [
		(None, {'fields': ['author', 'folder', 'name', 'location', 'description']}),
		('Date information', {'fields': ['date_created', 'date_modified']}),
	]
	inlines = [FileInline,]
	list_display = ('name', 'author', 'location', 'date_created', 'date_modified')

class BulletinInline(admin.TabularInline):
	model = Bulletin
	extra = 0

class FolderAdmin(admin.ModelAdmin):
	readonly_fields = ('date_created', 'date_modified',)
	fieldsets = [
		(None, {'fields': ['author', 'name', 'location', 'description']}),
		('Date information', {'fields': ['date_created', 'date_modified']}),
	]
	inlines = [BulletinInline,]
	list_display = ('name', 'author', 'location', 'date_created', 'date_modified')

class FileAccessAdmin(admin.ModelAdmin):
	fieldsets = [
		(None, {'fields': ['reader', 'file']}),
	]
	list_display = ('reader', 'file')

admin.site.register(Folder, FolderAdmin)
admin.site.register(Bulletin, BulletinAdmin)
admin.site.register(File, FileAdmin)
admin.site.register(FileAccess, FileAccessAdmin)
