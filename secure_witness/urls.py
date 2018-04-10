from django.conf.urls import patterns, url
import views

urlpatterns = patterns('',
    url(r'^$', views.home, name='home'),

    # login and logout
    url(r'^user/new/$', views.new_user, name='new_user'),
    url(r'^user/login/$', views.user_login, name='existing_user'),
    url(r'^user/logout/$', 'django.contrib.auth.views.logout', { 'next_page': 'home', }, name='logout'),

    # password reset
    url(r'^reset_password/$', 'django.contrib.auth.views.password_reset',  { 'post_reset_redirect' : '/reset_password/done/' }, name="password_reset"),
    (r'^reset_password/done/$', 'django.contrib.auth.views.password_reset_done'),
    url(r'^reset_password/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>.+)/$', 'django.contrib.auth.views.password_reset_confirm', { 'post_reset_redirect' : '/reset_password/complete/' }, name="password_reset_confirm"),
    (r'^reset_password/complete/$', 'django.contrib.auth.views.password_reset_complete'),

    # model operations
    url(r'^folder/(?P<folder_id>\d+)/copy/$', views.copy_folder, name='copy_folder'),
    url(r'^folder/(?P<folder_id>\d+)/delete/$', views.delete_folder, name='delete_folder'),
    url(r'^folder/(?P<folder_id>\d+)/edit/$', views.edit_folder, name='edit_folder'),
    url(r'^folder/(?P<folder_id>\d+)/$', views.get_folder, name='get_folder'),
    url(r'^folder/new/$', views.new_folder, name='new_folder'),
    url(r'^bulletin/(?P<bulletin_id>\d+)/copy/$', views.copy_bulletin, name='copy_bulletin'),
    url(r'^bulletin/(?P<bulletin_id>\d+)/delete/$', views.delete_bulletin, name='delete_bulletin'),
    url(r'^bulletin/(?P<bulletin_id>\d+)/edit/$', views.edit_bulletin, name='edit_bulletin'),
    url(r'^bulletin/(?P<bulletin_id>\d+)/$', views.get_bulletin, name='get_bulletin'),
    url(r'^bulletin/(?P<bulletin_id>\d+)/comment/$', views.post_comment, name='post_comment'),
    url(r'^folder/(?P<folder_id>\d+)/bulletin/new/$', views.new_bulletin, name='new_bulletin'),
    url(r'^bulletin/(?P<bulletin_id>\d+)/file/new/$', views.new_file, name='new_file'),
    url(r'^bulletin/search/$', views.search_bulletins, name='search_bulletins'),
    url(r'^file/(?P<file_id>\d+)/$', views.get_file, name='get_file'),
    url(r'^file/(?P<file_id>\d+)/give_access/$', views.give_access, name='give_access'),
    url(r'^file/(?P<file_id>\d+)/delete/$', views.delete_file, name='delete_file'),
)
