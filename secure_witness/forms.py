from models import Folder, Bulletin, User
from django import forms
from django.core.exceptions import ValidationError

class LoginForm(forms.Form):
    username = forms.CharField()
    password = forms.CharField(
        widget=forms.PasswordInput(),
    )
    def __init__(self, *args, **kwargs):
        super(LoginForm, self).__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

class UploadFileForm(forms.Form):
    file = forms.FileField()
    encrypt = forms.CharField(
        required=False,
        max_length=128,
        label='Encryption password (leave blank to keep unencrypted)',
        widget=forms.PasswordInput(),
    )
    def __init__(self, *args, **kwargs):
        super(UploadFileForm, self).__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

class FolderForm(forms.ModelForm):
    class Meta:
        model = Folder
        fields = ('name', 'location', 'description')
    required_css_class = 'required'
    name = forms.CharField(
        required = True,
        max_length = 128,
        label = 'Folder Name:',
        )
    location = forms.CharField(
        required = False,
        max_length = 128,
        label = 'Location:',
        )
    description = forms.CharField(
        required = False,
        max_length = 1024,
        label = 'Description:',
        widget = forms.Textarea(),
        )
    def __init__(self, *args, **kwargs):
        super(FolderForm, self).__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'
    def clean(self):
        return self.cleaned_data

class BulletinForm(forms.ModelForm):
    class Meta:
        model = Bulletin
        fields = ('name', 'location', 'description')
    required_css_class = 'required'
    name = forms.CharField(
        required = True,
        max_length = 128,
        label = 'Bulletin Name:',
        )
    location = forms.CharField(
        required = False,
        max_length = 128,
        label = 'Location:',
        )
    description = forms.CharField(
        required = False,
        max_length = 1024,
        label = 'Description:',
        widget = forms.Textarea(),
        )
    def __init__(self, *args, **kwargs):
        super(BulletinForm, self).__init__(*args, **kwargs)
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

    def clean(self):
        return self.cleaned_data

class BulletinSearchForm(forms.Form):
    CHAR_FIELD_CHOICES = (
        ('NO', ''),
        ('EQ', 'is exactly'),
        ('CT', 'contains'),
    )

    author_check = forms.ChoiceField(choices=CHAR_FIELD_CHOICES, required=False)
    author_username = forms.CharField(max_length=128, required=False)
    bulletin_check = forms.ChoiceField(choices=CHAR_FIELD_CHOICES, required=False)
    bulletin_name = forms.CharField(max_length=128, required=False)
    created_after_year = forms.IntegerField(required=False, min_value=1, max_value=9999)
    created_after_month = forms.IntegerField(required=False, min_value=1, max_value=12)
    created_after_day = forms.IntegerField(required=False, min_value=1, max_value=31)
    created_after_hour = forms.IntegerField(required=False, min_value=0, max_value=23)
    created_after_minute = forms.IntegerField(required=False, min_value=0, max_value=59)
    created_after_second = forms.IntegerField(required=False, min_value=0, max_value=59)
    created_before_year = forms.IntegerField(required=False, min_value=1, max_value=9999)
    created_before_month = forms.IntegerField(required=False, min_value=1, max_value=12)
    created_before_day = forms.IntegerField(required=False, min_value=1, max_value=31)
    created_before_hour = forms.IntegerField(required=False, min_value=0, max_value=23)
    created_before_minute = forms.IntegerField(required=False, min_value=0, max_value=59)
    created_before_second = forms.IntegerField(required=False, min_value=0, max_value=59)
    modified_after_year = forms.IntegerField(required=False, min_value=1, max_value=9999)
    modified_after_month = forms.IntegerField(required=False, min_value=1, max_value=12)
    modified_after_day = forms.IntegerField(required=False, min_value=1, max_value=31)
    modified_after_hour = forms.IntegerField(required=False, min_value=0, max_value=23)
    modified_after_minute = forms.IntegerField(required=False, min_value=0, max_value=59)
    modified_after_second = forms.IntegerField(required=False, min_value=0, max_value=59)
    modified_before_year = forms.IntegerField(required=False, min_value=1, max_value=9999)
    modified_before_month = forms.IntegerField(required=False, min_value=1, max_value=12)
    modified_before_day = forms.IntegerField(required=False, min_value=1, max_value=31)
    modified_before_hour = forms.IntegerField(required=False, min_value=0, max_value=23)
    modified_before_minute = forms.IntegerField(required=False, min_value=0, max_value=59)
    modified_before_second = forms.IntegerField(required=False, min_value=0, max_value=59)
    location_check = forms.ChoiceField(choices=CHAR_FIELD_CHOICES, required=False)
    location = forms.CharField(max_length=128, required=False)
    description_check = forms.ChoiceField(choices=CHAR_FIELD_CHOICES, required=False)
    description = forms.CharField(max_length=128, required=False)


class GiveAccessForm(forms.Form):
    reader = None
    author_password = forms.CharField(required=False, widget=forms.PasswordInput())

    def __init__(self, file, *args, **kwargs):
        super(GiveAccessForm, self).__init__(*args, **kwargs)
        self.fields['reader'] = forms.ModelMultipleChoiceField(queryset = User.objects.exclude(
            pk__in = file.fileaccess_set.values('reader__pk'),
        ))
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

class CommentForm(forms.Form):
    text = forms.CharField(max_length = 128, widget = forms.Textarea(attrs={
        'placeholder': 'Have anything to say?',
        'rows': '4',
        'cols': '80',
    }))
