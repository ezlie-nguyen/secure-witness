import tempfile
from base64 import urlsafe_b64encode, urlsafe_b64decode
from datetime import datetime

from django.core.exceptions import ObjectDoesNotExist
from django.core.files import File as DFile
from django.core.urlresolvers import reverse
from django.shortcuts import render, get_object_or_404
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth import authenticate, login
from django.contrib.auth.models import User
from django.utils import timezone
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

import forms
from models import File, Folder, Bulletin, UserKeys, FileAccess, Comment
from util import EncryptedFileWrapper
from util import create_encryption_params
from util import get_encryption_params
from util import generate_keys_for_user
from util import give_file_access

def home(request, folder_id = None):
    if not request.user.is_authenticated():
        return render(request, 'secure_witness/home.html', {
            'user': request.user,
            'logged_in': False,
            'form': forms.LoginForm(),
            })
    else:
        if not folder_id == None:
            folder = Folder.objects.get(pk = folder_id)
            folder.delete()
        return render(request, 'secure_witness/home.html', {
                'user': request.user,
                'folders': Folder.objects.filter(author = request.user),
                'logged_in': True,
                'form': forms.LoginForm(),
    })

def new_user(request):
    if request.method == 'POST':
        if User.objects.filter(username=request.POST['username']):
            return render(request, 'secure_witness/new_user.html', {
                'username_fail': True,
                'logged_in': request.user.is_authenticated(),
                'form': forms.LoginForm(),
            })
        if request.POST['password'] != request.POST['confirm_password']:
            return render(request, 'secure_witness/new_user.html', {
                    'password_fail': True,
                    'logged_in': request.user.is_authenticated(),
                    'form': forms.LoginForm(),
                    })

        u = User()
        u.username = request.POST['username']
        u.set_password(request.POST['password'])
        u.save()
        uk = generate_keys_for_user(u, request.POST['password'])
        uk.save()

        user = authenticate(username=u.username, password=request.POST['password'])
        if user is not None:
            if user.is_active:
                login(request, user)
                
                if not hasattr(user, 'userkeys'):
                    uk = generate_keys_for_user(user, password)
                    uk.save()
                    
                return HttpResponseRedirect(reverse('home'), {
                            'logged_in': request.user.is_authenticated(),
                            'form': forms.LoginForm(),
                            })
            else:
                account_disabled = True
        else:
            invalid_login = True

    else:
        return render(request, 'secure_witness/new_user.html', {
                'logged_in': request.user.is_authenticated(),
                'form': forms.LoginForm(),
                })


def user_login(request, rand=Random.new()):
    account_disabled = False
    invalid_login = False
    invalid_user = False

    if request.method == 'POST':
        form = forms.LoginForm(request.POST)

        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']

            if not User.objects.filter(username = username):
                invalid_user = True

            user = authenticate(username=username, password=password)
            if user is not None:
                if user.is_active:
                        login(request, user)

                        if not hasattr(user, 'userkeys'):
                            uk = generate_keys_for_user(user, password)
                            uk.save()

                        return HttpResponseRedirect(reverse('home'), {
                                    'logged_in': request.user.is_authenticated(),
                                    'form': forms.LoginForm(),
                                    })
                else:
                    account_disabled = True
            else:
                invalid_login = True

    return render(request, 'secure_witness/login.html', {
        'user': request.user,
        'form': forms.LoginForm(),
        'account_disabled': account_disabled,
        'invalid_login': invalid_login,
        'logged_in': request.user.is_authenticated(),
        'invalid_user': invalid_user,
    })

def copy_folder(request, folder_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    if request.method == 'POST':
        form = forms.FolderForm(request.POST)
        filterargs = {'author': request.user, 'name': request.POST['name']}
        if Folder.objects.filter(**filterargs):
            return render(request, 'secure_witness/copy_folder.html', {
                'folder_taken': True,
                'folder': Folder.objects.get(pk = folder_id),
                'folder_id': folder_id,
                'user': request.user,
                'form': form,
                'logged_in': request.user.is_authenticated(),
            })
        if form.is_valid():
            original_folder = Folder.objects.get(pk = folder_id)
            folder = Folder(
                author = original_folder.author,
                name = request.POST['name'],
                date_created = original_folder.date_created,
                date_modified = original_folder.date_modified,
                location = request.POST['location'],
                description = request.POST['description']
                )
            folder.save()
            for original_bulletin in Bulletin.objects.filter(folder = original_folder):
                bulletin = Bulletin(
                    author = original_bulletin.author,
                    name = original_bulletin.name,
                    folder = folder,
                    date_created = original_bulletin.date_created,
                    date_modified = original_bulletin.date_modified,
                    location = original_bulletin.location,
                    description = original_bulletin.description
                    )
                bulletin.save()
                for original_file in File.objects.filter(bulletin = original_bulletin):
                    newFile = File(
                        author = original_file.author,
                        bulletin = bulletin,
                        content = original_file.content,
                        name = original_file.name,
                        rand = original_file.rand,
                        check = original_file.check,
                        encryption_params = original_file.encryption_params,
                        date_created = original_file.date_created,
                        date_modified = original_file.date_modified
                        )
                    newFile.save()
            return HttpResponseRedirect(reverse('home'), {
                    'logged_in': request.user.is_authenticated(),
                    'form': forms.LoginForm(),
                    })
    else:
        f = get_object_or_404(Folder, pk = folder_id)
        form = forms.FolderForm(instance = f)
    return render(request, 'secure_witness/copy_folder.html', {
            'folder_id': folder_id,
            'form': form,
            'folder': Folder.objects.get(pk = folder_id),
            'logged_in': request.user.is_authenticated(),
    })

def delete_folder(request, folder_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    folder = Folder.objects.get(pk = folder_id)
    folder.delete()
    return HttpResponseRedirect(reverse('home'), {
            'logged_in': request.user.is_authenticated(),
            'form': forms.LoginForm(),
            })

def edit_folder(request, folder_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    if request.method == 'POST':
        form = forms.FolderForm(request.POST)
        filterargs = {'author': request.user, 'name': request.POST['name']}
        if Folder.objects.filter(**filterargs).exclude(pk = folder_id):
            return render(request, 'secure_witness/edit_folder.html', {
                'folder_taken': True,
                'folder_id': folder_id,
                'user': request.user,
                'form': form,
                'folder': Folder.objects.get(pk = folder_id),
                'logged_in': request.user.is_authenticated(),
            })
        if form.is_valid():
            folder = Folder.objects.get(pk = folder_id)
            folder.name = request.POST['name']
            folder.location = request.POST['location']
            folder.description = request.POST['description']
            folder.save()
            return HttpResponseRedirect(reverse('home'), {
                    'logged_in': request.user.is_authenticated(),
                    'form': forms.LoginForm(),
                    })
    else:
        f = get_object_or_404(Folder, pk = folder_id)
        form = forms.FolderForm(instance = f)
    return render(request, 'secure_witness/edit_folder.html', {
            'folder_id': folder_id,
            'form': form,
            'folder': Folder.objects.get(pk = folder_id),
            'logged_in': request.user.is_authenticated(),
    })

def get_folder(request, folder_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    return render(request, 'secure_witness/folder.html', {
            'bulletins': Bulletin.objects.filter(folder = folder_id),
            'user': request.user,
            'folder_id': folder_id,
            'logged_in': request.user.is_authenticated(),
            'folder': get_object_or_404(Folder, pk = folder_id),
            })

def new_folder(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    if request.method == 'POST':
        form = forms.FolderForm(request.POST)
        filterargs = {'author': request.user, 'name': request.POST['name']}
        if Folder.objects.filter(**filterargs):
            return render(request, 'secure_witness/new_folder.html', {
                'folder_taken': True,
                'user': request.user,
                'form': form,
                'logged_in': request.user.is_authenticated(),
            })
        if form.is_valid():
            folder = Folder(
                author = request.user,
                name = request.POST['name'],
                date_created = datetime.now(),
                date_modified = datetime.now(),
                location = request.POST['location'],
                description = request.POST['description']
                )
            folder.save()
            return HttpResponseRedirect(reverse('home'), {
                    'logged_in': request.user.is_authenticated(),
                    'form': forms.LoginForm(),
                    })
    else:
        form = forms.FolderForm()
    return render(request, 'secure_witness/new_folder.html', {
            'form': form,
            'logged_in': request.user.is_authenticated(),
    })

def copy_bulletin(request, bulletin_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': request.user.is_authenticated(),
                'form': forms.LoginForm(),
                })

    if request.method == 'POST':
        form = forms.BulletinForm(request.POST)
        original_bulletin = Bulletin.objects.get(pk = bulletin_id)
        f = original_bulletin.folder
        filterargs = {'author': request.user, 'name': request.POST['name'], 'folder': f}
        if Bulletin.objects.filter(**filterargs):
            return render(request, 'secure_witness/copy_bulletin.html', {
                'bulletin_taken': True,
                'bulletin_id': bulletin_id,
                'bulletin': original_bulletin,
                'user': request.user,
                'form': form,
                'folder': f,
                'folder_id': f.pk,
                'logged_in': request.user.is_authenticated(),
            })
        if form.is_valid():
            bulletin = Bulletin(
                author = original_bulletin.author,
                name = request.POST['name'],
                folder = original_bulletin.folder,
                date_created = datetime.now(),
                date_modified = datetime.now(),
                location = request.POST['location'],
                description = request.POST['description']
                )
            bulletin.save()
            for original_file in File.objects.filter(bulletin = original_bulletin):
                newFile = File(
                    author = original_file.author,
                    bulletin = bulletin,
                    content = original_file.content,
                    # name = original_file.name,
                    name = 'test',
                    rand = original_file.rand,
                    check = original_file.check,
                    encryption_params = original_file.encryption_params,
                    date_created = datetime.now(),
                    date_modified = datetime.now(),
                    )
                newFile.save()
            return HttpResponseRedirect(reverse('get_folder', kwargs={'folder_id': bulletin.folder.pk}), {
                        'folder_id': bulletin.folder.pk,
                        'folder': bulletin.folder,
                        'logged_in': request.user.is_authenticated(),
                        })
    else:
        b = get_object_or_404(Bulletin, pk = bulletin_id)
        f = b.folder
        form = forms.BulletinForm(instance = b)
    return render(request, 'secure_witness/copy_bulletin.html', {
            'bulletin_id': bulletin_id,
            'form': form,
            'bulletin': Bulletin.objects.get(pk = bulletin_id),
            'logged_in': request.user.is_authenticated(),
            'folder': f,
            'folder_id': f.pk,
    })

def delete_file(request, file_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })
    f = File.objects.get(pk = file_id)
    bulletin = f.bulletin
    folder = bulletin.folder
    f.delete()
    return HttpResponseRedirect(reverse('get_bulletin', kwargs={'bulletin_id': bulletin.pk}), {
            'folder_id': folder.pk,
            'folder': folder,
            'bulletin_id': bulletin.pk,
            'bulletin': bulletin,
            'logged_in': request.user.is_authenticated(),
            })
    
def delete_bulletin(request, bulletin_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    bulletin = Bulletin.objects.get(pk = bulletin_id)
    folder = bulletin.folder
    bulletin.delete()
    return HttpResponseRedirect(reverse('get_folder', kwargs={'folder_id': folder.pk}), {
            'folder_id': folder.pk,
            'folder': folder,
            'logged_in': request.user.is_authenticated(),
            })

def edit_bulletin(request, bulletin_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    if request.method == 'POST':
        form = forms.BulletinForm(request.POST)
        bulletin = get_object_or_404(Bulletin, pk = bulletin_id)
        folder = bulletin.folder
        filterargs = {'author': request.user, 'name': request.POST['name'], 'folder': folder}
        if Bulletin.objects.filter(**filterargs).exclude(pk=bulletin_id):
            return render(request, 'secure_witness/edit_bulletin.html', {
                    'bulletin_taken': True,
                    'user': request.user,
                    'bulletin_id' : bulletin_id,
                    'bulletin': bulletin,
                    'form': form,
                    'folder': folder,
                    'folder_id' : folder.pk,
                    'logged_in': request.user.is_authenticated(),
                    })
        if form.is_valid():
            bulletin = Bulletin.objects.get(pk = bulletin_id)
            bulletin.name = request.POST['name']
            bulletin.location = request.POST['location']
            bulletin.description = request.POST['description']
            bulletin.save()
            folder = bulletin.folder
            return render(request, 'secure_witness/folder.html', {
                    'bulletins': Bulletin.objects.filter(folder = folder.pk),
                    'user': request.user,
                    'folder_id': folder.pk,
                    'form': form,
                    'logged_in': request.user.is_authenticated(),
                    'folder': folder,
                    })
    else:
        b = get_object_or_404(Bulletin, pk = bulletin_id)
        folder = b.folder
        form = forms.BulletinForm(instance=b)
        return render(request, 'secure_witness/edit_bulletin.html', {
                'bulletin_id' : bulletin_id,
                'folder': folder,
                'folder_id': folder.pk,
                'form': form,
                'bulletin': b,
                'logged_in': request.user.is_authenticated(),
                })

def new_bulletin(request, folder_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    if request.method == 'POST':
        form = forms.BulletinForm(request.POST)
        filterargs = {'author': request.user, 'name': request.POST['name']}
        if Bulletin.objects.filter(**filterargs):
            return render(request, 'secure_witness/new_bulletin.html', {
                    'bulletin_taken': True,
                    'user': request.user,
                    'folder_id' : folder_id,
                    'form': form,
                    'folder': get_object_or_404(Folder, pk = folder_id),
                    'logged_in': request.user.is_authenticated(),
                    })
        if form.is_valid():
            bulletin = Bulletin(
                author = request.user,
                folder = get_object_or_404(Folder, pk = folder_id),
                name = request.POST['name'],
                date_created = datetime.now(),
                date_modified = datetime.now(),
                location = request.POST['location'],
                description = request.POST['description']
                )
            bulletin.save()
            return render(request, 'secure_witness/folder.html', {
                    'bulletins': Bulletin.objects.filter(folder = folder_id),
                    'user': request.user,
                    'folder_id': folder_id,
                    'logged_in': request.user.is_authenticated(),
                    'folder': get_object_or_404(Folder, pk = folder_id),
                    })
    else:
        form = forms.BulletinForm()
    return render(request, 'secure_witness/new_bulletin.html', {
            'folder_id' : folder_id,
            'form': form,
            'folder': get_object_or_404(Folder, pk = folder_id),
            'logged_in': request.user.is_authenticated(),
    })

def get_bulletin(request, bulletin_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    bulletin = get_object_or_404(Bulletin, pk=bulletin_id)
    folder = bulletin.folder

    return render(request, 'secure_witness/bulletin.html', {
            'bulletin': bulletin,
            'files': File.objects.filter(bulletin = bulletin),
            'user': request.user,
            'bulletin_id': bulletin_id,
            'logged_in': request.user.is_authenticated(),
            'folder_id': folder.pk,
            'folder': get_object_or_404(Folder, pk = folder.pk),
            'comments': Comment.objects.filter(bulletin = bulletin).order_by('date_submitted'),
            'comment_form': forms.CommentForm(),
            })

def my_files(request):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    u = request.user
    files = File.objects.filter(author=u)
    return render(request, 'secure_witness/my_files.html', {
        'user': u,
        'files': files,
        'my_files': True,
        'logged_in': request.user.is_authenticated(),
    })

def handle_new_file(user, uploaded, bulletin_id, encryption_key=None, rand=Random.new()):
    if encryption_key == '':
        encryption_key = None

    r, c, ep, iv, encryption_key = create_encryption_params(encryption_key, rand)

    file = File(
        author=user,
        bulletin=Bulletin.objects.get(pk=bulletin_id),
        name=uploaded.name,
        content=uploaded,
        rand=r,
        check=c,
        encryption_params=ep,
        date_created=datetime.now(),
        date_modified=datetime.now(),
    )

    if encryption_key is not None:
        with tempfile.NamedTemporaryFile() as temp:
            cipher = AES.new(encryption_key, AES.MODE_CFB, iv)
            for chunk in uploaded.chunks():
                encrypted_chunk = cipher.encrypt(chunk)
                temp.write(encrypted_chunk)
            temp.seek(0)
            file.content = DFile(temp)
            file.save()
            give_file_access(user, user, file, encryption_key)
    else:
        file.save()


def new_file(request, bulletin_id):
    user = request.user
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    incorrect_password = False

    if request.method == 'POST':
        form = forms.UploadFileForm(request.POST, request.FILES)

        if form.is_valid():
            password = request.POST['encrypt']

            if password != '':
                r, c, iv, encryption_key = get_encryption_params(password, str(user.userkeys.rand), str(user.userkeys.check), user.userkeys.encryption_params)

                if r == c:
                    AES.new(encryption_key, AES.MODE_CFB, iv).decrypt(urlsafe_b64decode(str(user.userkeys.private_key)))

                    handle_new_file(user, request.FILES['file'], bulletin_id, password)
                    folder = Folder.objects.get(bulletin = bulletin_id)
                    return HttpResponseRedirect(reverse('get_bulletin', args=(bulletin_id,)), {
                            'bulletin_id': bulletin_id,
                            'logged_in': user.is_authenticated(),
                            'folder': folder,
                            'folder_id': folder.pk,
                            'bulletin': get_object_or_404(Bulletin, pk = bulletin_id),
                            })
                else:
                    incorrect_password = True

            else:
                handle_new_file(user, request.FILES['file'], bulletin_id, None)
                folder = Folder.objects.get(bulletin = bulletin_id)
                return HttpResponseRedirect(reverse('get_bulletin', args=(bulletin_id,)), {
                        'bulletin_id': bulletin_id,
                        'logged_in': user.is_authenticated(),
                        'folder': folder,
                        'folder_id': folder.pk,
                        'bulletin': get_object_or_404(Bulletin, pk = bulletin_id),
                        })

    else:
        form = forms.UploadFileForm()
    return render(request, 'secure_witness/upload.html', {
            'form': form,
            'user': user,
            'bulletin': get_object_or_404(Bulletin, pk = bulletin_id),
            'bulletin_id': bulletin_id,
            'folder': Folder.objects.get(bulletin = bulletin_id),
            'folder_id': Folder.objects.get(bulletin = bulletin_id).pk,
            'logged_in': user.is_authenticated(),
            'incorrect_password': incorrect_password,
            })

def get_file(request, file_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
                'logged_in': False,
                'form': forms.LoginForm(),
                })

    f = get_object_or_404(File, pk = file_id)
    logged_in = request.user.is_authenticated()

    if f.encryption_params != '':
        # if the file is encrypted, ask for the user's password

        fa = None
        try:
            fa = FileAccess.objects.get(reader = request.user, file = f)
        except ObjectDoesNotExist:
            pass

        if fa is None:
            return render(request, 'secure_witness/file_password.html', {
                'file_id': file_id,
                'logged_in': logged_in,
                'no_access': True,
            })

        if request.method == 'POST':
            # if the user has given his password, check if the password is correct
            password = request.POST['password']
            user = request.user
            r, c, iv, encryption_key = get_encryption_params(password, str(user.userkeys.rand), str(user.userkeys.check), user.userkeys.encryption_params)

            if r == c:
                # password is correct, let the user download
                private_key = AES.new(encryption_key, AES.MODE_CFB, iv).decrypt(urlsafe_b64decode(str(user.userkeys.private_key)))
                rsa_key = RSA.importKey(private_key)
                rsa_cipher = PKCS1_OAEP.new(rsa_key)
                aes_key = rsa_cipher.decrypt(urlsafe_b64decode(str(fa.key)))
                iv = urlsafe_b64decode(str(f.encryption_params.split('$')[2]))

                response = HttpResponse(EncryptedFileWrapper(f.content, aes_key, iv))
                response['Content-Length'] = f.content.size
                response['Content-Disposition'] = "attachment; filename=%s" % f.name
                return response

            else:
                # password is incorrect, try again
                return render(request, 'secure_witness/file_password.html', {
                    'file_id': file_id,
                    'password_fail': True,
                    'logged_in': logged_in,
                })

        else:
            # ask the user for a password
            return render(request, 'secure_witness/file_password.html', {
                'file_id': file_id,
                'password_fail': False,
                'logged_in': logged_in,
            })

    else:
        # if file is unencrypted, let the user download
        response = HttpResponse(EncryptedFileWrapper(f.content))
        response['Content-Length'] = f.content.size
        response['Content-Disposition'] = "attachment; filename=%s" % f.name
        return response


def give_access(request, file_id):
    file = get_object_or_404(File, pk=file_id)
    password_incorrect = False
    required_fields_missing = False

    if request.method == 'POST':
        form = forms.GiveAccessForm(file, request.POST)

        if form.is_valid():
            password = form.cleaned_data['author_password']
            r, c, iv, aes_key = get_encryption_params(password, str(file.rand), str(file.check), file.encryption_params)

            if r == c:
                for reader in form.cleaned_data['reader']:
                    give_file_access(request.user, reader, file, aes_key)

                bulletin = file.bulletin
                folder = bulletin.folder
                return HttpResponseRedirect(reverse('get_bulletin', args=(file.bulletin.pk,)), {
                        'bulletin_id': bulletin.pk,
                        'bulletin': bulletin,
                        'folder': folder,
                        'folder_id': folder.pk,
                        'logged_in': request.user.is_authenticated(),
                        })

            else:
                password_incorrect = True

        else:
            required_fields_missing = True

    else:
        form = forms.GiveAccessForm(file)

    return render(request, 'secure_witness/give_access.html', {
        'user': request.user,
        'file': file,
        'form': form,
        'password_incorrect': password_incorrect,
        'required_fields_missing': required_fields_missing,
        'logged_in': request.user.is_authenticated(),
        'bulletin': file.bulletin,
        'bulletin_id': file.bulletin.pk,
        'folder': file.bulletin.folder,
        'folder_id': file.bulletin.folder.pk,
    })


def search_bulletins(request):
    logged_in = request.user.is_authenticated()
    if request.method == 'POST':
        form = forms.BulletinSearchForm(request.POST)

        if form.is_valid():
            query = Bulletin.objects.all()

            ac = request.POST['author_check']
            if ac == 'EQ':
                query = query.filter(
                    author__username=request.POST['author_username'],
                )
            elif ac == 'CT':
                query = query.filter(
                    author__username__contains=request.POST['author_username'],
                )

            bc = request.POST['bulletin_check']
            if bc == 'EQ':
                query = query.filter(
                    name=request.POST['bulletin_name'],
                )
            elif bc == 'CT':
                query = query.filter(
                    name__contains=request.POST['bulletin_name'],
                )

            lc = request.POST['location_check']
            if lc == 'EQ':
                query = query.filter(
                    location=request.POST['location'],
                )
            elif lc == 'CT':
                query = query.filter(
                    location__contains=request.POST['location'],
                )

            dc = request.POST['description_check']
            if dc == 'EQ':
                query = query.filter(
                    description=request.POST['description'],
                )
            elif dc == 'CT':
                query = query.filter(
                    description__contains=request.POST['description'],
                )

            cay = int(request.POST['created_after_year'] or '1')
            camo = int(request.POST['created_after_month'] or '1')
            cad = int(request.POST['created_after_day'] or '1')
            cah = int(request.POST['created_after_hour'] or '0')
            cami = int(request.POST['created_after_minute'] or '0')
            cas = int(request.POST['created_after_second'] or '0')
            d = datetime(cay, camo, cad, cah, cami, cas)
            d = timezone.make_aware(d, timezone.get_default_timezone())
            query = query.filter(date_created__gte=d)

            cby = int(request.POST['created_before_year'] or '2038')
            cbmo = int(request.POST['created_before_month'] or '1')
            cbd = int(request.POST['created_before_day'] or '1')
            cbh = int(request.POST['created_before_hour'] or '0')
            cbmi = int(request.POST['created_before_minute'] or '0')
            cbs = int(request.POST['created_before_second'] or '0')
            d = datetime(cby, cbmo, cbd, cbh, cbmi, cbs)
            d = timezone.make_aware(d, timezone.get_default_timezone())
            query = query.filter(date_created__lt=d)

            may = int(request.POST['modified_after_year'] or '1')
            mamo = int(request.POST['modified_after_month'] or '1')
            mad = int(request.POST['modified_after_day'] or '1')
            mah = int(request.POST['modified_after_hour'] or '0')
            mami = int(request.POST['modified_after_minute'] or '0')
            mas = int(request.POST['modified_after_second'] or '0')
            d = datetime(may, mamo, mad, mah, mami, mas)
            d = timezone.make_aware(d, timezone.get_default_timezone())
            query = query.filter(date_modified__gte=d)

            mby = int(request.POST['modified_before_year'] or '2038')
            mbmo = int(request.POST['modified_before_month'] or '1')
            mbd = int(request.POST['modified_before_day'] or '1')
            mbh = int(request.POST['modified_before_hour'] or '0')
            mbmi = int(request.POST['modified_before_minute'] or '0')
            mbs = int(request.POST['modified_before_second'] or '0')
            d = datetime(mby, mbmo, mbd, mbh, mbmi, mbs)
            d = timezone.make_aware(d, timezone.get_default_timezone())
            query = query.filter(date_modified__lt=d)

            return render(request, 'secure_witness/search_bulletins_results.html', {
                'results': query,
                'search': True,
                'logged_in': logged_in,
            })

    else:
        form = forms.BulletinSearchForm()

    return render(request, 'secure_witness/search_bulletins.html', {
        'form': form,
        'search': True,
        'logged_in': logged_in,
    })


def post_comment(request, bulletin_id):
    if not request.user.is_authenticated():
        return HttpResponseRedirect(reverse('existing_user'), {
            'logged_in': False,
            'form': forms.LoginForm(),
        })

    bulletin = get_object_or_404(Bulletin, pk=bulletin_id)
    user = request.user

    if request.method == 'POST':
        form = forms.CommentForm(request.POST)

        if form.is_valid():
            text = form.cleaned_data['text']

            comment = Comment(
                bulletin = bulletin,
                user = user,
                text = text,
            )
            comment.save()

            return HttpResponseRedirect(reverse('get_bulletin', args=(bulletin_id,)))
