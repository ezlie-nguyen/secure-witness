from django.db import models
from django.contrib.auth.models import User

class Folder(models.Model):
    author = models.ForeignKey(User)
    name = models.CharField(max_length=128)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    location = models.CharField(max_length=128)
    description = models.CharField(max_length=1024)

    def __unicode__(self):
        return self.name

class Bulletin(models.Model):
    author = models.ForeignKey(User)
    folder = models.ForeignKey(Folder, null=True)
    name = models.CharField(max_length=128)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)
    location = models.CharField(max_length=128)
    description = models.CharField(max_length=1024)

    def __unicode__(self):
        return self.name

class File(models.Model):
    author = models.ForeignKey(User)
    bulletin = models.ForeignKey(Bulletin, null=True)
    content = models.FileField(upload_to='files')
    name = models.CharField(max_length=128)
    rand = models.CharField(max_length=24)  # 128 bits encoded in base64
    check = models.CharField(max_length=24)  # 'rand' encrypted with password hash, encoded in base64
    encryption_params = models.CharField(max_length=128)
    date_created = models.DateTimeField(auto_now_add=True)
    date_modified = models.DateTimeField(auto_now=True)

    def __unicode__(self):
        return self.name

class UserKeys(models.Model):
    user = models.OneToOneField(User)
    public_key = models.CharField(max_length=392)  # 2352 bits encoded in base64
    private_key = models.CharField(max_length=1592)  # 9536 encrypted with password hash, encoded in base64
    rand = models.CharField(max_length=24)  # 128 bits encoded in base64
    check = models.CharField(max_length=24)  # 'rand' encrypted with password hash, encoded in base64
    encryption_params = models.CharField(max_length=128)

    def __unicode__(self):
        return self.user.username

class FileAccess(models.Model):
    reader = models.ForeignKey(User)
    file = models.ForeignKey(File)
    key = models.CharField(max_length=344)  # 128 bits encrypted with reader's public key (becomes 2048 bits), encoded in base64

    def __unicode__(self):
        return self.reader.username

class Comment(models.Model):
    bulletin = models.ForeignKey(Bulletin)
    user = models.ForeignKey(User)
    date_submitted = models.DateTimeField(auto_now_add=True)
    text = models.CharField(max_length=140)
